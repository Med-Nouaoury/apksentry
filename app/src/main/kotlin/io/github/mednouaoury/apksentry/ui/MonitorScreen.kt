package io.github.mednouaoury.apksentry.ui

import android.app.Activity
import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.mednouaoury.apksentry.core.DomainKind
import io.github.mednouaoury.apksentry.net.ConnEvent
import io.github.mednouaoury.apksentry.net.Firewall
import io.github.mednouaoury.apksentry.net.MonitorMode
import io.github.mednouaoury.apksentry.net.MonitorSession
import io.github.mednouaoury.apksentry.net.NetMonitor
import io.github.mednouaoury.apksentry.net.NetMonitorService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private data class AppEntry(val pkg: String, val label: String, val system: Boolean)

@Composable
fun MonitorScreen() {
    val session by NetMonitor.session.collectAsStateWithLifecycle()
    val s = session
    if (s == null) MonitorSetup() else MonitorLive(s)
}

// =====================================================================
// اختيار التطبيق
// =====================================================================
@Composable
private fun MonitorSetup() {
    val ctx = LocalContext.current
    val cs = MaterialTheme.colorScheme
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
    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Surface(shape = MaterialTheme.shapes.extraLarge, color = cs.surfaceContainerLow, border = BorderStroke(1.dp, cs.outlineVariant)) {
                Box(Modifier.background(Brush.linearGradient(listOf(cs.secondary.copy(alpha = 0.20f), cs.primary.copy(alpha = 0.08f), Color.Transparent)))) {
                    Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        IconBadge(AppIcons.Wifi, cs.secondary, 56.dp)
                        Text("راقب اتصالات أي تطبيق", style = MaterialTheme.typography.headlineSmall)
                        Text(
                            "اختر تطبيقاً ثم استعمله. سترى كل موقع يحاول الوصول إليه، وتمنع ما تريد بضغطة. كل شيء على هاتفك عبر VPN محلي.",
                            style = MaterialTheme.typography.bodyMedium, color = cs.onSurfaceVariant,
                        )
                    }
                }
            }
        }
        item { FirewallCard() }
        privateDnsWarning(ctx)?.let { w -> item { FindingLine(w, StatusColors.warn()) } }
        error?.let { e -> item { FindingLine(e, StatusColors.bad()) } }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                ModeCard(AppIcons.Wifi, "مراقبة", "التطبيق يعمل عادي ونسجّل اتصالاته", mode == MonitorMode.WATCH, Modifier.weight(1f)) { mode = MonitorMode.WATCH }
                ModeCard(AppIcons.Block, "قطع الإنترنت", "دائم: يبقى حتى بعد الخروج وإعادة تشغيل الهاتف", mode == MonitorMode.BLOCK_ALL, Modifier.weight(1f)) { mode = MonitorMode.BLOCK_ALL }
            }
        }
        item {
            OutlinedTextField(
                value = query, onValueChange = { query = it }, singleLine = true,
                placeholder = { Text("ابحث عن تطبيق") },
                leadingIcon = { Icon(Icons.Filled.Search, null) },
                modifier = Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.extraLarge,
            )
        }
        if (filtered == null) item { Hint("تحميل قائمة التطبيقات...") }
        else items(filtered, key = { it.pkg }) { app ->
            AppRow(app, selected == app.pkg, onSelect = { selected = app.pkg }, onStart = { start(app) })
        }
    }
}

/** التطبيقات المقطوع عنها الإنترنت (محفوظة دائماً). */
@Composable
private fun FirewallCard() {
    val ctx = LocalContext.current
    val cs = MaterialTheme.colorScheme
    LaunchedEffect(Unit) { Firewall.load(ctx) }
    val blocked by Firewall.blocked.collectAsStateWithLifecycle()
    val running by Firewall.running.collectAsStateWithLifecycle()
    val attempts by Firewall.attempts.collectAsStateWithLifecycle()
    if (blocked.isEmpty()) return
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == Activity.RESULT_OK) NetMonitorService.refresh(ctx)
    }
    val bad = StatusColors.bad()
    SectionCard("تطبيقات بدون إنترنت", AppIcons.Block, if (running) bad else StatusColors.warn()) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Dot(if (running) StatusColors.ok() else StatusColors.warn(), 10.dp)
            Text(
                if (running) "الحظر يعمل، حتى بعد الخروج من ApkSentry" else "الحظر متوقف الآن: هذه التطبيقات لها إنترنت",
                style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f),
            )
            if (!running) Button(onClick = {
                val prep = VpnService.prepare(ctx)
                if (prep == null) NetMonitorService.refresh(ctx) else consent.launch(prep)
            }, shape = MaterialTheme.shapes.medium) { Text("شغّل") }
        }
        blocked.sorted().forEach { pkg ->
            BlockedRow(pkg, attempts[pkg] ?: 0) { Firewall.unblock(ctx, pkg) }
        }
        Hint("لكي يبقى الحظر مضموناً بعد إعادة تشغيل الهاتف، فعّل \"VPN دائم التشغيل\" لـ ApkSentry من إعدادات الـ VPN.")
        OutlinedButton(onClick = {
            runCatching { ctx.startActivity(android.content.Intent(android.provider.Settings.ACTION_VPN_SETTINGS)) }
        }, shape = MaterialTheme.shapes.medium) { Text("افتح إعدادات الـ VPN") }
    }
}

@Composable
private fun BlockedRow(pkg: String, attempts: Int, onUnblock: () -> Unit) {
    val ctx = LocalContext.current
    val cs = MaterialTheme.colorScheme
    val info by produceState<Pair<String, ImageBitmap?>>(pkg to null, pkg) {
        value = withContext(Dispatchers.IO) {
            val pm = ctx.packageManager
            val label = runCatching { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)
            label to runCatching { pm.getApplicationIcon(pkg).toBitmap(96, 96).asImageBitmap() }.getOrNull()
        }
    }
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        val bmp = info.second
        if (bmp != null) Image(bmp, null, Modifier.size(40.dp).clip(RoundedCornerShape(12.dp)))
        else IconBadge(AppIcons.Block, StatusColors.bad(), 40.dp)
        Column(Modifier.weight(1f)) {
            Text(info.first, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(if (attempts > 0) "منعنا $attempts محاولة اتصال" else "لا محاولات بعد", style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant)
        }
        OutlinedButton(onClick = onUnblock, shape = MaterialTheme.shapes.medium) { Text("أرجع الإنترنت") }
    }
}

@Composable
private fun ModeCard(icon: ImageVector, title: String, sub: String, checked: Boolean, modifier: Modifier, onClick: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    val accent = if (checked) cs.primary else cs.outlineVariant
    Surface(
        modifier.height(128.dp).clickable(onClick = onClick),
        shape = MaterialTheme.shapes.large,
        color = if (checked) cs.primary.copy(alpha = 0.12f) else cs.surfaceContainerLow,
        border = BorderStroke(if (checked) 2.dp else 1.dp, accent),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            IconBadge(icon, if (checked) cs.primary else cs.onSurfaceVariant, 32.dp)
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(sub, style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun AppRow(app: AppEntry, selected: Boolean, onSelect: () -> Unit, onStart: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    val ctx = LocalContext.current
    val icon by produceState<ImageBitmap?>(null, app.pkg) {
        value = withContext(Dispatchers.IO) {
            runCatching { ctx.packageManager.getApplicationIcon(app.pkg).toBitmap(96, 96).asImageBitmap() }.getOrNull()
        }
    }
    Surface(
        Modifier.fillMaxWidth().clickable(onClick = onSelect),
        shape = MaterialTheme.shapes.large,
        color = if (selected) cs.primary.copy(alpha = 0.10f) else cs.surfaceContainerLow,
        border = BorderStroke(1.dp, if (selected) cs.primary else cs.outlineVariant),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            val bmp = icon
            if (bmp != null) Image(bmp, null, Modifier.size(42.dp).clip(RoundedCornerShape(12.dp)))
            else IconBadge(AppIcons.File, cs.onSurfaceVariant, 42.dp)
            Column(Modifier.weight(1f)) {
                Text(app.label, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(app.pkg, style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (selected) Button(onClick = onStart, shape = MaterialTheme.shapes.medium) { Text("ابدأ") }
            else if (app.system) Pill("نظام", cs.onSurfaceVariant)
        }
    }
}

// =====================================================================
// أثناء المراقبة
// =====================================================================
private enum class Filter(val label: String) { ALL("الكل"), SUSPICIOUS("مشبوه"), UNUSUAL("غير مألوف"), BLOCKED("ممنوع") }

@Composable
private fun MonitorLive(s: MonitorSession) {
    val ctx = LocalContext.current
    val cs = MaterialTheme.colorScheme
    val events by NetMonitor.events.collectAsStateWithLifecycle()
    var filter by rememberSaveable { mutableStateOf(Filter.ALL) }
    val pulse by rememberInfiniteTransition(label = "pulse").animateFloat(
        0.3f, 1f, infiniteRepeatable(tween(900), RepeatMode.Reverse), label = "a",
    )
    val shown = events.filter {
        when (filter) {
            Filter.ALL -> true
            Filter.SUSPICIOUS -> it.kind == DomainKind.SUSPICIOUS
            Filter.UNUSUAL -> it.kind == DomainKind.UNUSUAL
            Filter.BLOCKED -> it.blocked
        }
    }
    val bad = StatusColors.bad()
    val warn = StatusColors.warn()
    val ok = StatusColors.ok()

    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Surface(shape = MaterialTheme.shapes.extraLarge, color = cs.surfaceContainerLow, border = BorderStroke(1.dp, cs.outlineVariant)) {
                Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Box(Modifier.size(12.dp).alpha(pulse).clip(CircleShape).background(if (s.mode == MonitorMode.BLOCK_ALL) bad else ok))
                        Text(if (s.mode == MonitorMode.BLOCK_ALL) "الإنترنت مقطوع (دائم)" else "مراقبة مباشرة", style = MaterialTheme.typography.labelLarge,
                            color = if (s.mode == MonitorMode.BLOCK_ALL) bad else ok)
                    }
                    Column {
                        Text(s.label, style = MaterialTheme.typography.headlineSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(s.pkg, style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant)
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        StatTile("${events.size}", "مواقع", cs.primary, Modifier.weight(1f))
                        StatTile("${events.count { it.kind == DomainKind.SUSPICIOUS }}", "مشبوهة", bad, Modifier.weight(1f))
                        StatTile("${events.count { it.kind == DomainKind.UNUSUAL }}", "غير مألوفة", warn, Modifier.weight(1f))
                        StatTile("${events.count { it.blocked }}", "ممنوعة", cs.onSurfaceVariant, Modifier.weight(1f))
                    }
                    Text(
                        if (s.mode == MonitorMode.BLOCK_ALL) "نسجّل كل ما يحاول التطبيق الوصول إليه، ولا نمرّر شيئاً. يبقى الإنترنت مقطوعاً عنه حتى لو خرجت من ApkSentry أو أعدت تشغيل الهاتف."
                        else "افتح التطبيق الآن واستعمله. المواقع تظهر هنا مباشرة.",
                        style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant,
                    )
                    if (s.mode == MonitorMode.BLOCK_ALL) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = { NetMonitorService.stop(ctx) }, modifier = Modifier.weight(1f), shape = MaterialTheme.shapes.medium) {
                                Text("رجوع")
                            }
                            FilledTonalButton(onClick = { Firewall.unblock(ctx, s.pkg); NetMonitorService.stop(ctx) }, modifier = Modifier.weight(1f), shape = MaterialTheme.shapes.medium) {
                                Text("أرجع له الإنترنت")
                            }
                        }
                    } else {
                        OutlinedButton(onClick = { NetMonitorService.stop(ctx) }, modifier = Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.medium) {
                            Text("إيقاف المراقبة")
                        }
                    }
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Filter.entries.forEach { f ->
                    val on = f == filter
                    Text(
                        f.label,
                        modifier = Modifier.clip(CircleShape)
                            .background(if (on) cs.primary else cs.surfaceContainerHigh)
                            .border(1.dp, if (on) cs.primary else cs.outlineVariant, CircleShape)
                            .clickable { filter = f }
                            .padding(horizontal = 14.dp, vertical = 7.dp),
                        color = if (on) cs.onPrimary else cs.onSurface,
                        style = MaterialTheme.typography.labelLarge,
                    )
                }
            }
        }
        if (shown.isEmpty()) item {
            Column(Modifier.fillMaxWidth().padding(vertical = 28.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                IconBadge(AppIcons.Globe, cs.onSurfaceVariant, 56.dp)
                Spacer(Modifier.height(10.dp))
                Hint(if (events.isEmpty()) "لا اتصالات بعد. افتح التطبيق واستعمله قليلاً." else "لا شيء في هذا التصنيف.")
            }
        }
        items(shown, key = { it.domain }) { e -> EventRow(e, canToggle = s.mode == MonitorMode.WATCH && !e.direct) }
        item {
            Hint(
                "نرى المواقع عبر طلبات DNS. بعد منع موقع، قد يحتاج التطبيق لإعادة تشغيل. " +
                    "الاتصال المباشر بعنوان IP لا يظهر إلا في وضع قطع الإنترنت.",
            )
        }
    }
}

@Composable
private fun EventRow(e: ConnEvent, canToggle: Boolean) {
    val cs = MaterialTheme.colorScheme
    val color = when (e.kind) {
        DomainKind.SUSPICIOUS -> StatusColors.bad()
        DomainKind.UNUSUAL -> StatusColors.warn()
        DomainKind.TRACKING -> StatusColors.info()
        DomainKind.KNOWN -> StatusColors.ok()
    }
    Surface(
        Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        color = if (e.kind == DomainKind.SUSPICIOUS) color.copy(alpha = 0.08f) else cs.surfaceContainerLow,
        border = BorderStroke(1.dp, if (e.kind == DomainKind.SUSPICIOUS) color.copy(alpha = 0.5f) else cs.outlineVariant),
    ) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Dot(color, 10.dp)
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(e.domain, style = MaterialTheme.typography.titleSmall, fontFamily = FontFamily.Monospace, maxLines = 2, overflow = TextOverflow.Ellipsis)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Pill(if (e.direct) "IP مباشر" else e.kind.label, color)
                    Text("${e.count}×", style = MaterialTheme.typography.labelMedium, color = cs.onSurfaceVariant)
                    if (e.blocked) Pill("ممنوع", cs.onSurfaceVariant)
                }
                if (e.kind == DomainKind.SUSPICIOUS) Text("يشبه اسم الموقع الذي أعاد توقيع التطبيق", style = MaterialTheme.typography.bodySmall, color = color)
                if (e.ips.isNotEmpty()) Text(e.ips.joinToString("  "), style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (canToggle) {
                if (e.blocked) OutlinedButton(onClick = { NetMonitor.toggleBlock(e.domain) }, shape = MaterialTheme.shapes.medium) { Text("سماح") }
                else FilledTonalButton(onClick = { NetMonitor.toggleBlock(e.domain) }, shape = MaterialTheme.shapes.medium) { Text("منع") }
            }
        }
    }
}

@Suppress("DEPRECATION")
private fun loadApps(ctx: Context): List<AppEntry> {
    val pm = ctx.packageManager
    return pm.getInstalledApplications(0)
        .filter { it.packageName != ctx.packageName && pm.getLaunchIntentForPackage(it.packageName) != null }
        .map { AppEntry(it.packageName, it.loadLabel(pm).toString(), it.flags and ApplicationInfo.FLAG_SYSTEM != 0) }
        .sortedWith(compareBy<AppEntry>({ it.system }, { it.label.lowercase() }))
}

/** إذا كان "DNS الخاص" مضبوطاً على اسم خادم، قد لا نرى طلبات التطبيق. */
private fun privateDnsWarning(ctx: Context): String? = try {
    if (Build.VERSION.SDK_INT < 28) null else {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val name = cm.activeNetwork?.let { cm.getLinkProperties(it)?.privateDnsServerName }
        if (name != null) "\"DNS الخاص\" مضبوط على $name. للمراقبة الكاملة اجعله \"تلقائي\" من إعدادات الشبكة." else null
    }
} catch (e: Exception) {
    null
}
