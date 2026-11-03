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
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * VPN محلي لتطبيق واحد فقط:
 * - وضع المراقبة: نمرّر طلبات DNS عبرنا فنرى كل موقع يطلبه التطبيق، ونستطيع منع موقع بعينه.
 * - وضع المنع الكامل: كل اتصالات التطبيق تمر عبرنا ولا نمرّر أي شيء (جدار حماية).
 * لا نغادر الهاتف ولا نرسل أي شيء لأي خادم غير خادم DNS الأصلي للشبكة.
 */
class NetMonitorService : VpnService() {
    companion object {
        const val ACTION_START = "io.github.mednouaoury.apksentry.START"
        const val ACTION_STOP = "io.github.mednouaoury.apksentry.STOP"
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

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, NetMonitorService::class.java).setAction(ACTION_STOP))
        }
    }

    @Volatile
    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    private var pool: ExecutorService? = null
    private var upstream: List<InetAddress> = emptyList()
    private val writeLock = Any()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVpn(intent)
            ACTION_STOP -> {
                stopVpn()
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun startVpn(intent: Intent) {
        stopVpn()
        val pkg = intent.getStringExtra(EXTRA_PKG) ?: return
        val label = intent.getStringExtra(EXTRA_LABEL) ?: pkg
        val mode = runCatching { MonitorMode.valueOf(intent.getStringExtra(EXTRA_MODE) ?: "") }.getOrDefault(MonitorMode.WATCH)
        NetMonitor.reset()
        upstream = currentDns()

        val builder = Builder()
            .setSession("ApkSentry: $label")
            .addAddress(VPN_ADDR, 32)
            .addDnsServer(DNS_ADDR)
            .addRoute(DNS_ADDR, 32)
            .setBlocking(true)
        if (mode == MonitorMode.BLOCK_ALL) {
            builder.addRoute("0.0.0.0", 0)
            builder.addAddress(VPN_ADDR6, 128)
            builder.addRoute("::", 0)
        }
        try {
            builder.addAllowedApplication(pkg)
        } catch (e: PackageManager.NameNotFoundException) {
            NetMonitor.error.value = "التطبيق غير مثبّت"
            stopSelf()
            return
        }
        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            null
        }
        if (pfd == null) {
            NetMonitor.error.value = "تعذّر تشغيل المراقبة. تأكد أنك قبلت طلب VPN، وأنه لا يوجد VPN آخر يعمل."
            stopSelf()
            return
        }
        tun = pfd
        pool = Executors.newFixedThreadPool(4)
        NetMonitor.session.value = MonitorSession(pkg, label, mode, signerTokens(pkg))
        reader = Thread({ loop(pfd, mode) }, "apksentry-vpn").also { it.start() }
    }

    private fun stopVpn() {
        reader?.interrupt()
        reader = null
        try { tun?.close() } catch (_: IOException) { }
        tun = null
        pool?.shutdownNow()
        pool = null
        NetMonitor.session.value = null
    }

    private fun loop(pfd: ParcelFileDescriptor, mode: MonitorMode) {
        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        val buf = ByteArray(32_767)
        val tokens = NetMonitor.session.value?.signerTokens ?: emptySet()
        try {
            while (!Thread.currentThread().isInterrupted) {
                val n = input.read(buf)
                if (n < 0) break
                if (n == 0) continue
                val q = DnsPackets.parseQuery(buf, n)
                if (q != null) {
                    handleDns(q, output, mode, tokens)
                } else if (mode == MonitorMode.BLOCK_ALL) {
                    // اتصال مباشر بعنوان IP: نسجّله ولا نمرّره
                    DnsPackets.parseRaw(buf, n)?.let { c ->
                        NetMonitor.record("${c.dstIp}:${c.dstPort} (${c.protocol})", DomainKind.UNUSUAL, true, direct = true)
                    }
                }
            }
        } catch (_: IOException) {
        } catch (_: Exception) {
        }
    }

    private fun handleDns(q: DnsQuery, out: FileOutputStream, mode: MonitorMode, tokens: Set<String>) {
        val kind = DomainIntel.classify(q.domain, tokens)
        if (mode == MonitorMode.BLOCK_ALL || NetMonitor.isBlocked(q.domain)) {
            write(out, DnsPackets.wrapResponse(q, DnsPackets.nxdomain(q)))
            NetMonitor.record(q.domain, kind, true)
            return
        }
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
