package io.github.mednouaoury.apksentry.net

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap

/**
 * التطبيقات المقطوع عنها الإنترنت بشكل دائم.
 * القائمة محفوظة في الهاتف: تبقى بعد إغلاق ApkSentry وبعد إعادة تشغيل الهاتف.
 */
object Firewall {
    private const val PREFS = "firewall"
    private const val KEY = "blocked"

    private val _blocked = MutableStateFlow<Set<String>>(emptySet())
    val blocked: StateFlow<Set<String>> = _blocked.asStateFlow()

    /** هل جدار الحماية (VPN) يعمل الآن؟ */
    val running = MutableStateFlow(false)

    /** عدد محاولات الاتصال التي منعناها لكل تطبيق (منذ تشغيل الجدار). */
    private val counts = ConcurrentHashMap<String, Int>()
    val attempts = MutableStateFlow<Map<String, Int>>(emptyMap())

    @Volatile
    private var loaded = false

    fun load(ctx: Context) {
        if (loaded) return
        synchronized(this) {
            if (loaded) return
            _blocked.value = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getStringSet(KEY, emptySet())!!.toSet()
            loaded = true
        }
    }

    private fun save(ctx: Context, set: Set<String>) {
        _blocked.value = set
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putStringSet(KEY, set).apply()
    }

    fun isBlocked(ctx: Context, pkg: String): Boolean { load(ctx); return pkg in _blocked.value }

    /** يقطع الإنترنت عن التطبيق ويشغّل الجدار (يجب أن يكون إذن VPN مقبولاً مسبقاً). */
    fun block(ctx: Context, pkg: String) {
        load(ctx)
        save(ctx, _blocked.value + pkg)
        NetMonitorService.refresh(ctx)
    }

    /** يرجع الإنترنت للتطبيق. إذا لم يبق تطبيق محظور، يتوقف الجدار. */
    fun unblock(ctx: Context, pkg: String) {
        load(ctx)
        save(ctx, _blocked.value - pkg)
        counts.remove(pkg)
        attempts.value = counts.toMap()
        NetMonitorService.refresh(ctx)
    }

    fun recordAttempt(pkg: String) {
        counts.merge(pkg, 1, Int::plus)
        attempts.value = counts.toMap()
    }

    /** هل يمكن تشغيل الجدار بدون سؤال المستخدم (إذن VPN مقبول)؟ */
    fun canStartSilently(ctx: Context): Boolean = try { VpnService.prepare(ctx) == null } catch (e: Exception) { false }
}

/** بعد إعادة تشغيل الهاتف أو تحديث ApkSentry: نعيد قطع الإنترنت عن التطبيقات المحفوظة. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        Firewall.load(ctx)
        if (Firewall.blocked.value.isNotEmpty() && Firewall.canStartSilently(ctx)) {
            try { NetMonitorService.refresh(ctx) } catch (e: Exception) { }
        }
    }
}
