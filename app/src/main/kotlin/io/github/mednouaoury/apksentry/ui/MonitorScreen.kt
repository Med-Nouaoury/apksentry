package io.github.mednouaoury.apksentry.ui

import android.app.Activity
import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.mednouaoury.apksentry.core.DomainKind
import io.github.mednouaoury.apksentry.net.ConnEvent
import io.github.mednouaoury.apksentry.net.MonitorMode
import io.github.mednouaoury.apksentry.net.MonitorSession
import io.github.mednouaoury.apksentry.net.NetMonitor
import io.github.mednouaoury.apksentry.net.NetMonitorService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private data class AppEntry(val pkg: String, val label: String)

@Composable
fun MonitorScreen() {
    val session by NetMonitor.session.collectAsStateWithLifecycle()
    val s = session
    if (s == null) MonitorSetup() else MonitorLive(s)
}

// ---------------- اختيار التطبيق ----------------
@Composable
private fun MonitorSetup() {
    val ctx = LocalContext.current
    val error by NetMonitor.error.collectAsStateWithLifecycle()
    var apps by remember { mutableStateOf<List<AppEntry>?>(null) }
    var query by rememberSaveable { mutableStateOf("") }
    var selected by rememberSaveable { mutableStateOf<String?>(null) }
    var mode by rememberSaveable { mutableStateOf(MonitorMode.WATCH) }
    LaunchedEffect(Unit) { apps = withContext(Dispatchers.IO) { loadApps(ctx) } }

    val pending = remember { mutableStateOf<AppEntry?>(null) }
    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        val app = pending.value
        if (res.resultCode == Activity.RESULT_OK && app != null) NetMonitorService.start(ctx, app.pkg, app.label, mode)
        else if (res.resultCode != Activity.RESULT_OK) NetMonitor.error.value = "لم تقبل طلب VPN، فلا يمكن المراقبة"
    }

    fun start(app: AppEntry) {
        NetMonitor.error.value = null
        val prep = VpnService.prepare(ctx)
        if (prep == null) NetMonitorService.start(ctx, app.pkg, app.label, mode)
        else { pending.value = app; vpnPermission.launch(prep) }
    }

    val filtered = apps?.filter { query.isBlank() || it.label.contains(query, true) || it.pkg.contains(query, true) }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item {
            Text("راقب اتصالات تطبيق", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(6.dp))
            Text(
                "اختر تطبيقاً، ثم افتحه واستعمله. سترى كل موقع يحاول الاتصال به، ويمكنك منع أي موقع، أو قطع الإنترنت عنه كلياً. " +
                    "المراقبة على هاتفك فقط، عبر VPN محلي.",
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        privateDnsWarning(ctx)?.let { w -> item { Text(w, color = StatusColors.warn(), style = MaterialTheme.typography.bodySmall) } }
        error?.let { e -> item { Text(e, color = StatusColors.bad()) } }
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    ModeRow("مراقبة فقط (التطبيق يعمل عادي)", mode == MonitorMode.WATCH) { mode = MonitorMode.WATCH }
                    ModeRow("منع الإنترنت كلياً عن هذا التطبيق (مع تسجيل ما يحاول الاتصال به)", mode == MonitorMode.BLOCK_ALL) { mode = MonitorMode.BLOCK_ALL }
                }
            }
        }
        item {
            OutlinedTextField(
                value = query, onValueChange = { query = it }, singleLine = true,
                label = { Text("ابحث عن تطبيق") }, modifier = Modifier.fillMaxWidth(),
            )
        }
        if (filtered == null) item { Text("تحميل قائمة التطبيقات...") }
        else items(filtered, key = { it.pkg }) { app ->
            val isSel = selected == app.pkg
            Card(
                Modifier.fillMaxWidth().clickable { selected = app.pkg },
                colors = if (isSel) CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer) else CardDefaults.cardColors(),
            ) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(app.label, fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Hint(app.pkg)
                    }
                    if (isSel) Button(onClick = { start(app) }) { Text("ابدأ") }
                }
            }
        }
    }
}

@Composable
private fun ModeRow(text: String, checked: Boolean, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick), verticalAlignment = Alignment.CenterVertically) {
        RadioButton(selected = checked, onClick = onClick)
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}

// ---------------- أثناء المراقبة ----------------
@Composable
private fun MonitorLive(s: MonitorSession) {
    val ctx = LocalContext.current
    val events by NetMonitor.events.collectAsStateWithLifecycle()
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("نراقب: ${s.label}", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Hint(s.pkg)
                    Text(
                        if (s.mode == MonitorMode.BLOCK_ALL) "الإنترنت مقطوع عن هذا التطبيق، ونسجّل ما يحاول الوصول إليه."
                        else "افتح التطبيق الآن واستعمله. المواقع تظهر هنا مباشرة.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    val suspicious = events.count { it.kind == DomainKind.SUSPICIOUS }
                    val unusual = events.count { it.kind == DomainKind.UNUSUAL }
                    Text("المواقع: ${events.size}، غير مألوفة: $unusual، مشبوهة: $suspicious",
                        color = if (suspicious > 0) StatusColors.bad() else if (unusual > 0) StatusColors.warn() else StatusColors.ok())
                    OutlinedButton(onClick = { NetMonitorService.stop(ctx) }) { Text("إيقاف المراقبة") }
                }
            }
        }
        if (events.isEmpty()) item { Hint("لا اتصالات بعد. افتح التطبيق واستعمله قليلاً.") }
        items(events, key = { it.domain }) { e -> EventRow(e, canToggle = s.mode == MonitorMode.WATCH && !e.direct) }
        item {
            Hint(
                "ملاحظة: نرى المواقع عبر طلبات DNS. إذا منعت موقعاً، قد يحتاج التطبيق لإعادة تشغيل حتى يتوقف عن استعمال عنوان محفوظ. " +
                    "التطبيقات التي تتصل بعنوان IP مباشرة لا تظهر هنا إلا في وضع المنع الكامل.",
            )
        }
    }
}

@Composable
private fun EventRow(e: ConnEvent, canToggle: Boolean) {
    val color = when (e.kind) {
        DomainKind.SUSPICIOUS -> StatusColors.bad()
        DomainKind.UNUSUAL -> StatusColors.warn()
        DomainKind.TRACKING -> StatusColors.info()
        DomainKind.KNOWN -> StatusColors.ok()
    }
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(e.domain, fontWeight = FontWeight.Bold, maxLines = 2, overflow = TextOverflow.Ellipsis)
                Text(
                    (if (e.direct) "اتصال مباشر بعنوان IP" else e.kind.label) +
                        " · ${e.count} مرة" + if (e.blocked) " · ممنوع" else "",
                    color = color, style = MaterialTheme.typography.bodySmall,
                )
                if (e.kind == DomainKind.SUSPICIOUS)
                    Text("يشبه اسم الموقع الذي أعاد توقيع التطبيق", color = StatusColors.bad(), style = MaterialTheme.typography.bodySmall)
                if (e.ips.isNotEmpty()) Hint(e.ips.joinToString("، "))
            }
            if (canToggle) {
                OutlinedButton(onClick = { NetMonitor.toggleBlock(e.domain) }) { Text(if (e.blocked) "سماح" else "منع") }
            }
        }
    }
}

@Suppress("DEPRECATION")
private fun loadApps(ctx: Context): List<AppEntry> {
    val pm = ctx.packageManager
    return pm.getInstalledApplications(0)
        .filter { it.packageName != ctx.packageName && pm.getLaunchIntentForPackage(it.packageName) != null }
        .map { AppEntry(it.packageName, it.loadLabel(pm).toString()) }
        .sortedWith(compareBy<AppEntry>({ isSystem(pm, it.pkg) }, { it.label.lowercase() }))
}

@Suppress("DEPRECATION")
private fun isSystem(pm: android.content.pm.PackageManager, pkg: String): Boolean = try {
    pm.getApplicationInfo(pkg, 0).flags and ApplicationInfo.FLAG_SYSTEM != 0
} catch (e: Exception) {
    true
}

/** إذا كان "DNS الخاص" مضبوطاً على اسم خادم، قد لا نرى طلبات التطبيق. */
private fun privateDnsWarning(ctx: Context): String? = try {
    if (Build.VERSION.SDK_INT < 28) null else {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val name = cm.activeNetwork?.let { cm.getLinkProperties(it)?.privateDnsServerName }
        if (name != null) "تنبيه: \"DNS الخاص\" مضبوط على $name. للمراقبة الكاملة اجعله \"تلقائي\" من إعدادات الشبكة." else null
    }
} catch (e: Exception) {
    null
}
