package io.github.mednouaoury.apksentry.ui

import android.content.Context
import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.mednouaoury.apksentry.ScanViewModel
import io.github.mednouaoury.apksentry.UiState
import io.github.mednouaoury.apksentry.core.RiskLevel
import io.github.mednouaoury.apksentry.core.ScanResult
import io.github.mednouaoury.apksentry.core.Section
import io.github.mednouaoury.apksentry.core.Tone
import io.github.mednouaoury.apksentry.net.NetMonitor

// =====================================================================
// الهيكل العام: رأس + محتوى + شريط تنقّل سفلي
// =====================================================================
@Composable
fun ApkSentryApp(vm: ScanViewModel) {
    val state by vm.state.collectAsStateWithLifecycle()
    val monitoring by NetMonitor.session.collectAsStateWithLifecycle()
    var tab by rememberSaveable { mutableStateOf(0) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) { tab = 0; vm.scan(uri) }
    }
    BackHandler(enabled = tab == 0 && (state is UiState.Done || state is UiState.Failed)) { vm.reset() }
    BackHandler(enabled = tab == 1) { tab = 0 }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = { AppHeader() },
        bottomBar = {
            NavigationBar(containerColor = MaterialTheme.colorScheme.surfaceContainerLow) {
                NavigationBarItem(
                    selected = tab == 0, onClick = { tab = 0 },
                    icon = { Icon(AppIcons.Shield, null) }, label = { Text("الفحص") },
                )
                NavigationBarItem(
                    selected = tab == 1, onClick = { tab = 1 },
                    icon = {
                        Box {
                            Icon(AppIcons.Wifi, null)
                            if (monitoring != null) Box(Modifier.align(Alignment.TopEnd)) { Dot(StatusColors.ok(), 8.dp) }
                        }
                    },
                    label = { Text(if (monitoring != null) "المراقبة (تعمل)" else "المراقبة") },
                )
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            Crossfade(targetState = tab, label = "tab") { t ->
                if (t == 1) MonitorScreen() else when (val s = state) {
                    UiState.Idle -> HomeScreen(vm) { picker.launch(arrayOf("*/*")) }
                    is UiState.Scanning -> ScanningScreen(s) { vm.cancel() }
                    is UiState.Done -> ResultScreen(s.result, vm) { vm.reset() }
                    is UiState.Failed -> ErrorScreen(s.message) { vm.reset() }
                }
            }
        }
    }
}

@Composable
private fun AppHeader() {
    Row(
        Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.background).statusBarsPadding()
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            Modifier.size(42.dp).clip(RoundedCornerShape(14.dp))
                .background(Brush.linearGradient(listOf(MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.secondary))),
            contentAlignment = Alignment.Center,
        ) { Icon(AppIcons.Verified, null, tint = Color.White, modifier = Modifier.size(24.dp)) }
        Column {
            Text("ApkSentry", style = MaterialTheme.typography.titleLarge)
            Text("حارس تطبيقاتك قبل التثبيت", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

// =====================================================================
// الشاشة الرئيسية
// =====================================================================
@Composable
private fun HomeScreen(vm: ScanViewModel, onPick: () -> Unit) {
    var showSettings by rememberSaveable { mutableStateOf(false) }
    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item { HomeHero(onPick) }
        item { Text("ماذا نفحص؟", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 4.dp)) }
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                FeatureRow(
                    Feature(AppIcons.Verified, "التوقيع", "هل الملف من المطور؟ وهل تغيّر بعد توقيعه؟"),
                    Feature(AppIcons.Code, "تتبّع بياناتك", "هل تصل رسائلك أو موقعك أو ما تنسخه للإنترنت؟"),
                )
                FeatureRow(
                    Feature(AppIcons.Bug, "سلوك الفيروسات", "أكثر من 20 نمطاً لعائلات خبيثة معروفة"),
                    Feature(AppIcons.Chip, "المكتبات native", "استدعاءات نظام مخفية وكود مشفّر"),
                )
                FeatureRow(
                    Feature(AppIcons.Shield, "الثغرات", "SSL مكسور، تشفير ضعيف، WebView خطير"),
                    Feature(AppIcons.Database, "قواعد الفيروسات", "MalwareBazaar و VirusTotal (اختياري)"),
                )
            }
        }
        item { SettingsCard(vm, showSettings) { showSettings = !showSettings } }
        item {
            Text(
                "الفحص يتم كاملاً على هاتفك، ولا يُرفع أي ملف. الفحص ثابت (لا يشغّل التطبيق)، ولمعرفة ما يفعله وقت التشغيل استعمل تبويب المراقبة.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            )
        }
    }
}

@Composable
private fun HomeHero(onPick: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    Surface(shape = MaterialTheme.shapes.extraLarge, color = cs.surfaceContainerLow, border = BorderStroke(1.dp, cs.outlineVariant)) {
        Box(Modifier.background(Brush.linearGradient(listOf(cs.primary.copy(alpha = 0.22f), cs.secondary.copy(alpha = 0.10f), Color.Transparent)))) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
                Box(
                    Modifier.size(64.dp).clip(RoundedCornerShape(20.dp)).background(cs.primary.copy(alpha = 0.18f)),
                    contentAlignment = Alignment.Center,
                ) { Icon(AppIcons.Verified, null, tint = cs.primary, modifier = Modifier.size(36.dp)) }
                Text("افحص التطبيق قبل تثبيته", style = MaterialTheme.typography.headlineSmall)
                Text(
                    "اختر ملف APK أو APKS أو XAPK، وسنقرأه من الداخل ونخبرك إن كان معدّلاً أو يخفي سلوكاً خطيراً.",
                    style = MaterialTheme.typography.bodyMedium, color = cs.onSurfaceVariant,
                )
                Button(
                    onClick = onPick,
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    shape = MaterialTheme.shapes.medium,
                ) {
                    Icon(AppIcons.Folder, null, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(10.dp))
                    Text("اختر ملفاً للفحص", style = MaterialTheme.typography.titleMedium)
                }
            }
        }
    }
}

private class Feature(val icon: ImageVector, val title: String, val sub: String)

@Composable
private fun FeatureRow(a: Feature, b: Feature) {
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        FeatureTile(a, Modifier.weight(1f))
        FeatureTile(b, Modifier.weight(1f))
    }
}

@Composable
private fun FeatureTile(f: Feature, modifier: Modifier) {
    val cs = MaterialTheme.colorScheme
    Surface(modifier.height(132.dp), shape = MaterialTheme.shapes.large, color = cs.surfaceContainerLow, border = BorderStroke(1.dp, cs.outlineVariant)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            IconBadge(f.icon, cs.primary, 34.dp)
            Text(f.title, style = MaterialTheme.typography.titleSmall)
            Text(f.sub, style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun SettingsCard(vm: ScanViewModel, open: Boolean, onToggle: () -> Unit) {
    val rotation by animateFloatAsState(if (open) 180f else 0f, label = "arrow")
    SectionCard(
        title = "إعدادات متقدمة",
        icon = AppIcons.Tune,
        accent = MaterialTheme.colorScheme.secondary,
        modifier = Modifier.clickable(onClick = onToggle),
        trailing = { Icon(Icons.Filled.KeyboardArrowDown, null, modifier = Modifier.rotate(rotation)) },
    ) {
        if (!open) Hint("مفاتيح قواعد الفيروسات، بصمة المطور، وتتبّع البيانات")
        AnimatedVisibility(open) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = vm.mbKey, onValueChange = vm::updateMbKey, singleLine = true,
                    label = { Text("مفتاح MalwareBazaar") }, visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.medium,
                )
                Hint("قاعدة بيانات مجانية للفيروسات المعروفة. المفتاح مجاني من auth.abuse.ch. نرسل البصمة فقط.")
                OutlinedTextField(
                    value = vm.vtKey, onValueChange = vm::updateVtKey, singleLine = true,
                    label = { Text("مفتاح VirusTotal") }, visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.medium,
                )
                Hint("أكثر من 70 برنامج حماية. الحساب المجاني بطيء (4 طلبات في الدقيقة). نرسل البصمة فقط.")
                OutlinedTextField(
                    value = vm.expectedCert, onValueChange = vm::updateExpectedCert, singleLine = true,
                    label = { Text("بصمة شهادة المطور (SHA-256)") },
                    modifier = Modifier.fillMaxWidth(), shape = MaterialTheme.shapes.medium,
                )
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("تتبّع البيانات الشخصية", style = MaterialTheme.typography.bodyMedium)
                        Hint("أعمق، لكنه أبطأ قليلاً في التطبيقات الكبيرة")
                    }
                    Switch(checked = vm.dataFlow, onCheckedChange = vm::updateDataFlow)
                }
            }
        }
    }
}

@Composable
internal fun Hint(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

// =====================================================================
// أثناء الفحص
// =====================================================================
private val STAGES = listOf("قراءة الملف والتوقيع", "تحليل الكود", "تتبّع البيانات والثغرات", "المكتبات native", "قواعد بيانات الفيروسات", "تجهيز النتيجة")

private fun stageOf(msg: String): Int = when {
    "كتابة النتيجة" in msg -> 5
    "VirusTotal" in msg || "MalwareBazaar" in msg || "بصمة" in msg -> 4
    ".so" in msg -> 3
    "تدفّق" in msg || "الثغرات" in msg -> 2
    "classes" in msg || ".dex" in msg -> 1
    else -> 0
}

@Composable
private fun ScanningScreen(s: UiState.Scanning, onCancel: () -> Unit) {
    val view = LocalView.current
    DisposableEffect(Unit) {
        view.keepScreenOn = true
        onDispose { view.keepScreenOn = false }
    }
    val cs = MaterialTheme.colorScheme
    var stage by remember { mutableStateOf(0) }
    LaunchedEffect(s.message) { stage = maxOf(stage, stageOf(s.message)) }
    val progress by animateFloatAsState(s.fraction.coerceIn(0f, 1f), tween(400), label = "p")
    val spin by rememberInfiniteTransition(label = "spin").animateFloat(
        0f, 360f, infiniteRepeatable(tween(1600, easing = LinearEasing)), label = "a",
    )

    LazyColumn(
        Modifier.fillMaxSize(), contentPadding = PaddingValues(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        item {
            Box(Modifier.size(200.dp).padding(top = 8.dp), contentAlignment = Alignment.Center) {
                val track = cs.outlineVariant
                val primary = cs.primary
                val secondary = cs.secondary
                Canvas(Modifier.fillMaxSize()) {
                    val w = 12.dp.toPx()
                    val tl = Offset(w / 2, w / 2)
                    val sz = Size(size.width - w, size.height - w)
                    drawArc(track, 0f, 360f, false, tl, sz, style = Stroke(w))
                    drawArc(primary, -90f, 360f * progress, false, tl, sz, style = Stroke(w, cap = StrokeCap.Round))
                    drawArc(secondary.copy(alpha = 0.6f), spin, 40f, false, Offset(w * 2, w * 2), Size(size.width - w * 4, size.height - w * 4), style = Stroke(w / 3, cap = StrokeCap.Round))
                }
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("${(progress * 100).toInt()}%", fontSize = 40.sp, fontWeight = FontWeight.Bold, fontFamily = PlexArabic, color = cs.primary)
                    Text("جارٍ الفحص", style = MaterialTheme.typography.labelMedium, color = cs.onSurfaceVariant)
                }
            }
        }
        item {
            Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(s.fileName, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center, maxLines = 2, overflow = TextOverflow.Ellipsis)
                Crossfade(targetState = s.message, label = "msg") { m ->
                    Text(m, style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant, textAlign = TextAlign.Center, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
        }
        item {
            Surface(shape = MaterialTheme.shapes.large, color = cs.surfaceContainerLow, border = BorderStroke(1.dp, cs.outlineVariant), modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    STAGES.forEachIndexed { i, name ->
                        val done = i < stage
                        val current = i == stage
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            when {
                                done -> Icon(Icons.Filled.CheckCircle, null, tint = StatusColors.ok(), modifier = Modifier.size(20.dp))
                                current -> Box(Modifier.size(20.dp), contentAlignment = Alignment.Center) { Dot(cs.primary, 12.dp) }
                                else -> Box(Modifier.size(20.dp), contentAlignment = Alignment.Center) { Dot(cs.outlineVariant, 10.dp) }
                            }
                            Text(
                                name, style = MaterialTheme.typography.bodyMedium,
                                color = if (done || current) cs.onSurface else cs.onSurfaceVariant,
                                fontWeight = if (current) FontWeight.SemiBold else FontWeight.Normal,
                            )
                        }
                    }
                }
            }
        }
        item { Hint("الملفات الكبيرة مثل الألعاب قد تأخذ بضع دقائق. أبقِ التطبيق مفتوحاً.") }
        item { OutlinedButton(onClick = onCancel, shape = MaterialTheme.shapes.medium) { Text("إلغاء الفحص") } }
    }
}

// =====================================================================
// النتيجة
// =====================================================================
@Composable
private fun levelColor(level: RiskLevel): Color = when (level) {
    RiskLevel.LOW -> StatusColors.ok()
    RiskLevel.LOW_MEDIUM -> StatusColors.warn()
    RiskLevel.MEDIUM -> StatusColors.warn()
    RiskLevel.HIGH -> StatusColors.bad()
}

private fun levelTitle(level: RiskLevel) = when (level) {
    RiskLevel.LOW -> "لا توجد علامات خطيرة"
    RiskLevel.LOW_MEDIUM -> "ملاحظات بسيطة"
    RiskLevel.MEDIUM -> "يستحق الحذر"
    RiskLevel.HIGH -> "خطر مرتفع"
}

private fun levelShort(level: RiskLevel) = when (level) {
    RiskLevel.LOW -> "منخفض"
    RiskLevel.LOW_MEDIUM -> "منخفض إلى متوسط"
    RiskLevel.MEDIUM -> "متوسط"
    RiskLevel.HIGH -> "مرتفع"
}

@Composable
private fun ResultScreen(r: ScanResult, vm: ScanViewModel, onNew: () -> Unit) {
    val ctx = LocalContext.current
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri != null) runCatching { ctx.contentResolver.openOutputStream(uri)?.use { it.write(r.toText().toByteArray(Charsets.UTF_8)) } }
    }
    val expanded = remember { mutableStateMapOf<Int, Boolean>() }
    var trusted by remember { mutableStateOf(vm.isTrusted(r)) }
    val bad = StatusColors.bad()
    val warn = StatusColors.warn()
    val ok = StatusColors.ok()
    val info = StatusColors.info()
    val dangers = if (r.behaviors.isNotEmpty()) r.dangers.filterNot { it.message.startsWith("سلوك: ") } else r.dangers

    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item { VerdictHero(r) }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatTile("${r.behaviors.size}", "سلوك خبيث", if (r.behaviors.isEmpty()) ok else bad, Modifier.weight(1f))
                StatTile("${r.vulns.size}", "ثغرات", if (r.vulns.any { it.severity >= 3 }) bad else if (r.vulns.isNotEmpty()) warn else ok, Modifier.weight(1f))
                StatTile("${r.secrets.size}", "أسرار", if (r.secrets.any { it.suspicious }) bad else if (r.secrets.isNotEmpty()) warn else ok, Modifier.weight(1f))
                StatTile("${r.unusualDomains.size}", "مواقع غريبة", if (r.unusualDomains.isNotEmpty()) warn else ok, Modifier.weight(1f))
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                val pad = PaddingValues(horizontal = 6.dp, vertical = 10.dp)
                Button(onClick = { share(ctx, r) }, modifier = Modifier.weight(1f), shape = MaterialTheme.shapes.medium, contentPadding = pad) {
                    Icon(Icons.Filled.Share, null, Modifier.size(16.dp)); Spacer(Modifier.width(4.dp)); Text("مشاركة", maxLines = 1, softWrap = false)
                }
                FilledTonalButton(
                    onClick = { saver.launch("apksentry_${r.fileName.substringBeforeLast('.')}.txt") },
                    modifier = Modifier.weight(1f), shape = MaterialTheme.shapes.medium, contentPadding = pad,
                ) { Text("حفظ", maxLines = 1, softWrap = false) }
                OutlinedButton(onClick = onNew, modifier = Modifier.weight(1f), shape = MaterialTheme.shapes.medium, contentPadding = pad) {
                    Icon(Icons.Filled.Refresh, null, Modifier.size(16.dp)); Spacer(Modifier.width(4.dp)); Text("ملف آخر", maxLines = 1, softWrap = false)
                }
            }
        }
        if (r.behaviors.isNotEmpty()) item {
            SectionCard("سلوكيات تشبه برامج خبيثة معروفة", AppIcons.Bug, bad) {
                r.behaviors.forEach { FindingLine(it.message, bad, badge = "${it.weight}") }
            }
        }
        item {
            SectionCard("علامات الخطر", AppIcons.Shield, if (dangers.isEmpty()) ok else bad) {
                if (dangers.isEmpty()) Text("لا شيء ✔", color = ok)
                dangers.forEach { FindingLine(it.message, if (it.weight >= 15) bad else warn, badge = "${it.weight}") }
            }
        }
        item {
            SectionCard("علامات التعديل", AppIcons.Code, if (r.mods.isEmpty()) ok else warn) {
                if (r.mods.isEmpty()) Text("لا شيء، يبدو أصلياً ✔", color = ok)
                else Hint("التعديل ليس خطراً بحد ذاته، لكنه يعني أن التطبيق ليس كما نشره المطور.")
                r.mods.forEach { FindingLine(it.message, warn, badge = "${it.weight}") }
            }
        }
        if (r.vulns.isNotEmpty()) item {
            SectionCard("ثغرات في التطبيق نفسه", AppIcons.Block, if (r.vulns.any { it.severity >= 3 }) bad else warn) {
                Hint("أخطاء أمنية تجعل التطبيق سهل الاختراق، وليست سلوكاً خبيثاً. لا تدخل في درجة الخطر.")
                r.vulns.forEach { v ->
                    val (label, c) = when (v.severity) { 3 -> "عالية" to bad; 2 -> "متوسطة" to warn; else -> "منخفضة" to info }
                    FindingLine(v.title, c, badge = label, sub = v.where.ifEmpty { null })
                }
            }
        }
        if (r.secrets.isNotEmpty()) item {
            SectionCard("أسرار مكتوبة داخل التطبيق", AppIcons.Key, if (r.secrets.any { it.suspicious }) bad else warn) {
                r.secrets.forEach { FindingLine(it.kind, if (it.suspicious) bad else warn, sub = it.masked) }
            }
        }
        if (r.advice.isNotEmpty()) item {
            SectionCard("نصائح", AppIcons.Verified, info) {
                r.advice.forEach { FindingLine(it, info) }
            }
        }
        if (r.unusualDomains.isNotEmpty()) item {
            SectionCard("مواقع غير مألوفة في الكود", AppIcons.Globe, warn, trailing = { Pill("${r.unusualDomains.size}", warn) }) {
                SelectionContainer {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        r.unusualDomains.take(40).forEach { d ->
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Dot(warn, 6.dp); Text(d, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
                            }
                        }
                    }
                }
            }
        }
        if (r.packageName != null && r.signers.isNotEmpty()) item {
            SectionCard("التوقيع الرسمي", AppIcons.Verified, if (trusted) ok else MaterialTheme.colorScheme.primary) {
                if (trusted) Text("هذا التوقيع محفوظ في قائمتك الموثوقة ✔", color = ok)
                else {
                    Hint("إذا كان هذا الملف من مصدر رسمي (المطور أو Google Play)، احفظ توقيعه. أي نسخة لاحقة بتوقيع مختلف ستُكشف.")
                    FilledTonalButton(onClick = { vm.trustSigner(r); trusted = true }, shape = MaterialTheme.shapes.medium) {
                        Text("هذا ملف رسمي: احفظ توقيعه")
                    }
                }
            }
        }
        if (r.notes.isNotEmpty()) item {
            SectionCard("ملاحظات", AppIcons.File, MaterialTheme.colorScheme.onSurfaceVariant) {
                r.notes.forEach { Hint("• $it") }
            }
        }
        item {
            Text("التفاصيل التقنية", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 6.dp))
        }
        itemsIndexed(r.sections) { i, sec ->
            DetailCard(sec, expanded[i] == true) { expanded[i] = expanded[i] != true }
        }
        item {
            Text(
                "فحص ثابت: لا يشغّل التطبيق، ولا يوجد فحص يضمن الأمان 100%. مدة الفحص ${r.durationMs / 1000} ثانية.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun VerdictHero(r: ScanResult) {
    val cs = MaterialTheme.colorScheme
    val color = levelColor(r.level)
    val modColor = if (r.isModified) StatusColors.warn() else StatusColors.ok()
    Surface(shape = MaterialTheme.shapes.extraLarge, color = cs.surfaceContainerLow, border = BorderStroke(1.dp, color.copy(alpha = 0.35f))) {
        Box(Modifier.background(Brush.verticalGradient(listOf(color.copy(alpha = 0.20f), Color.Transparent)))) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                    Box(Modifier.size(56.dp).clip(RoundedCornerShape(18.dp)).background(color.copy(alpha = 0.18f)), contentAlignment = Alignment.Center) {
                        Icon(
                            if (r.level == RiskLevel.LOW) AppIcons.Verified else Icons.Filled.Warning, null,
                            tint = color, modifier = Modifier.size(32.dp),
                        )
                    }
                    Column(Modifier.weight(1f)) {
                        Text(levelTitle(r.level), style = MaterialTheme.typography.headlineSmall, color = color)
                        Text(r.fileName, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        r.packageName?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                    }
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                    ScoreGauge(r.riskScore, "درجة الخطر", levelShort(r.level), color, Modifier.weight(1f))
                    ScoreGauge(r.modScore, "درجة التعديل", if (r.isModified) "معدّل" else "أصلي", modColor, Modifier.weight(1f))
                }
                Text(r.level.explanation, style = MaterialTheme.typography.bodyMedium, color = cs.onSurfaceVariant)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (r.integrityVerified) Pill("✔ التوقيع سليم", StatusColors.ok())
                    if (r.signers.size > 1) Pill("شهادات مختلفة!", StatusColors.bad())
                }
            }
        }
    }
}

@Composable
private fun DetailCard(sec: Section, open: Boolean, onToggle: () -> Unit) {
    val cs = MaterialTheme.colorScheme
    val rotation by animateFloatAsState(if (open) 180f else 0f, label = "arrow")
    Surface(shape = MaterialTheme.shapes.large, color = cs.surfaceContainerLow, border = BorderStroke(1.dp, cs.outlineVariant), modifier = Modifier.fillMaxWidth()) {
        Column {
            Row(
                Modifier.fillMaxWidth().clickable(onClick = onToggle).padding(16.dp),
                verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                IconBadge(AppIcons.File, cs.primary, 32.dp)
                Text(sec.title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                Icon(Icons.Filled.KeyboardArrowDown, null, modifier = Modifier.rotate(rotation))
            }
            AnimatedVisibility(open) {
                SelectionContainer {
                    Column(
                        Modifier.fillMaxWidth().background(cs.surfaceContainerLowest.copy(alpha = 0.5f)).padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        sec.lines.forEach { l ->
                            if (l.text.isEmpty()) Spacer(Modifier.height(6.dp))
                            else Text(
                                l.text,
                                style = if (l.tone == Tone.HEAD) MaterialTheme.typography.titleSmall else MaterialTheme.typography.bodySmall,
                                color = StatusColors.forTone(l.tone),
                                fontFamily = if (l.text.contains("SHA-256") || l.text.startsWith("\"")) FontFamily.Monospace else null,
                                modifier = Modifier.padding(start = (l.indent * 12).dp, top = if (l.tone == Tone.HEAD) 6.dp else 0.dp),
                            )
                        }
                    }
                }
            }
        }
    }
}

// =====================================================================
// خطأ
// =====================================================================
@Composable
private fun ErrorScreen(message: String, onBack: () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        IconBadge(AppIcons.Block, StatusColors.bad(), 80.dp)
        Spacer(Modifier.height(20.dp))
        Text("تعذّر فحص الملف", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Text(message, textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(24.dp))
        Button(onClick = onBack, shape = MaterialTheme.shapes.medium) { Text("رجوع") }
    }
}

private fun share(ctx: Context, r: ScanResult) {
    val text = r.toText().let { if (it.length > 200_000) it.take(200_000) + "\n..." else it }
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_SUBJECT, "تقرير ApkSentry: ${r.fileName}")
        putExtra(Intent.EXTRA_TEXT, text)
    }
    ctx.startActivity(Intent.createChooser(send, "مشاركة التقرير"))
}
