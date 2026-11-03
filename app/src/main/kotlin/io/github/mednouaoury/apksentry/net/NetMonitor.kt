package io.github.mednouaoury.apksentry.net

import io.github.mednouaoury.apksentry.core.DomainKind
import kotlinx.coroutines.flow.MutableStateFlow
import java.util.concurrent.ConcurrentHashMap

/** اتصال واحد في السجل (موقع، أو عنوان مباشر في وضع المنع الكامل). */
data class ConnEvent(
    val domain: String,
    val kind: DomainKind,
    val blocked: Boolean,
    val count: Int,
    val firstSeen: Long,
    val lastSeen: Long,
    val ips: List<String>,
    /** اتصال مباشر بعنوان IP بدون DNS. */
    val direct: Boolean = false,
)

enum class MonitorMode { WATCH, BLOCK_ALL }

data class MonitorSession(val pkg: String, val label: String, val mode: MonitorMode, val signerTokens: Set<String>)

/** حالة المراقبة، مشتركة بين خدمة VPN والواجهة. */
object NetMonitor {
    val session = MutableStateFlow<MonitorSession?>(null)
    val events = MutableStateFlow<List<ConnEvent>>(emptyList())
    val error = MutableStateFlow<String?>(null)

    private val blocked: MutableSet<String> = ConcurrentHashMap.newKeySet()
    private val log = ConcurrentHashMap<String, ConnEvent>()

    fun isBlocked(domain: String): Boolean = blocked.any { domain == it || domain.endsWith(".$it") }

    fun toggleBlock(domain: String) {
        if (!blocked.remove(domain)) blocked.add(domain)
        log[domain]?.let { log[domain] = it.copy(blocked = domain in blocked) }
        publish()
    }

    fun reset() {
        log.clear()
        blocked.clear()
        events.value = emptyList()
        error.value = null
    }

    fun record(domain: String, kind: DomainKind, isBlocked: Boolean, ips: List<String> = emptyList(), direct: Boolean = false) {
        val now = System.currentTimeMillis()
        log.compute(domain) { _, old ->
            if (old == null) ConnEvent(domain, kind, isBlocked, 1, now, now, ips, direct)
            else old.copy(count = old.count + 1, lastSeen = now, blocked = isBlocked, ips = (old.ips + ips).distinct().take(6))
        }
        publish()
    }

    private fun publish() {
        events.value = log.values.sortedWith(compareBy<ConnEvent> { it.kind.ordinal }.thenByDescending { it.lastSeen })
    }
}
