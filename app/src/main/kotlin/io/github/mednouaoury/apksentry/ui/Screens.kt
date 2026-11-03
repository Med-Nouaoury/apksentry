package io.github.mednouaoury.apksentry.ui

import android.content.Context
import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.mednouaoury.apksentry.ScanViewModel
import io.github.mednouaoury.apksentry.UiState
import io.github.mednouaoury.apksentry.core.Finding
import io.github.mednouaoury.apksentry.core.RiskLevel
import io.github.mednouaoury.apksentry.core.ScanResult
import io.github.mednouaoury.apksentry.core.Section
import io.github.mednouaoury.apksentry.core.Tone

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApkSentryApp(vm: ScanViewModel) {
    val state by vm.state.collectAsStateWithLifecycle()
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.scan(uri)
    }
    BackHandler(enabled = state is UiState.Done || state is UiState.Failed) { vm.reset() }

    Scaffold(topBar = { TopAppBar(title = { Text("ApkSentry", fontWeight = FontWeight.Bold) }) }) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val s = state) {
                UiState.Idle -> HomeScreen(vm) { picker.launch(arrayOf("*/*")) }
                is UiState.Scanning -> ScanningScreen(s) { vm.cancel() }
                is UiState.Done -> ResultScreen(s.result, vm) { vm.reset() }
                is UiState.Failed -> ErrorScreen(s.message) { vm.reset() }
            }
        }
    }
}

// ---------------- الشاشة الرئيسية ----------------
@Composable
private fun HomeScreen(vm: ScanViewModel, onPick: () -> Unit) {
    var showSettings by rememberSaveable { mutableStateOf(false) }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("افحص التطبيق قبل تثبيته", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(
            "اختر ملف APK أو APKS أو XAPK. الفحص يتم كاملاً على هاتفك: الصلاحيات، التوقيع ومقارنته بالنسخة الرسمية، " +
                "الكود المضاف، تتبّع بياناتك من مصدرها حتى الإنترنت، سلوكيات الفيروسات المعروفة، أدوات الحماية والتشفير، " +
                "وتحليل المكتبات native من الداخل.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(onClick = onPick, modifier = Modifier.fillMaxWidth().height(56.dp)) {
            Text("اختر ملفاً للفحص", fontSize = 17.sp)
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.fillMaxWidth()) {
                Row(
                    Modifier.fillMaxWidth().clickable { showSettings = !showSettings }.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("إعدادات اختيارية", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                    Text(if (showSettings) "▲" else "▼")
                }
                if (showSettings) {
                    Column(
                        Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedTextField(
                            value = vm.vtKey,
                            onValueChange = vm::updateVtKey,
                            label = { Text("مفتاح VirusTotal API") },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Hint("نرسل بصمة الملفات (SHA-256) فقط، لا الملفات نفسها. الحساب المجاني يسمح بـ 4 طلبات في الدقيقة، فيصبح الفحص أبطأ.")
                        OutlinedTextField(
                            value = vm.mbKey,
                            onValueChange = vm::updateMbKey,
                            label = { Text("مفتاح MalwareBazaar") },
                            singleLine = true,
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Hint("قاعدة بيانات مجانية للفيروسات المعروفة. المفتاح مجاني من auth.abuse.ch. نرسل البصمة فقط.")
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text("تتبّع البيانات الشخصية", style = MaterialTheme.typography.bodyMedium)
                                Hint("أعمق لكنه أبطأ قليلاً في التطبيقات الكبيرة.")
                            }
                            Switch(checked = vm.dataFlow, onCheckedChange = vm::updateDataFlow)
                        }
                        OutlinedTextField(
                            value = vm.expectedCert,
                            onValueChange = vm::updateExpectedCert,
                            label = { Text("بصمة شهادة المطور الرسمية (SHA-256)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Hint("إذا عرفت بصمة المطور، يتأكد الفحص أن الملف موقَّع منه هو.")
                    }
                }
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("حدود الفحص", style = MaterialTheme.typography.titleSmall)
                Hint(
                    "هذا فحص ثابت: لا يشغّل التطبيق. الكود المخفي داخل مكتبات native لا يظهر سلوكه هنا. " +
                        "لذلك راقب أول تشغيل بتطبيق PCAPdroid، وامنع التطبيق من الإنترنت إذا لم يكن يحتاجه.",
                )
            }
        }
    }
}

@Composable
private fun Hint(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

// ---------------- أثناء الفحص ----------------
@Composable
private fun ScanningScreen(s: UiState.Scanning, onCancel: () -> Unit) {
    val view = LocalView.current
    DisposableEffect(Unit) {
        view.keepScreenOn = true
        onDispose { view.keepScreenOn = false }
    }
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(s.fileName, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
        Spacer(Modifier.height(20.dp))
        LinearProgressIndicator(progress = { s.fraction.coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(8.dp))
        Text("${(s.fraction.coerceIn(0f, 1f) * 100).toInt()}%", fontWeight = FontWeight.Bold)
        Text(
            s.message,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))
        Hint("الملفات الكبيرة مثل الألعاب قد تأخذ بضع دقائق. أبقِ التطبيق مفتوحاً.")
        Spacer(Modifier.height(16.dp))
        OutlinedButton(onClick = onCancel) { Text("إلغاء") }
    }
}

// ---------------- النتيجة ----------------
@Composable
private fun ResultScreen(r: ScanResult, vm: ScanViewModel, onNew: () -> Unit) {
    val ctx = LocalContext.current
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri != null) {
            runCatching {
                ctx.contentResolver.openOutputStream(uri)?.use { it.write(r.toText().toByteArray(Charsets.UTF_8)) }
            }
        }
    }
    val expanded = remember { mutableStateMapOf<Int, Boolean>() }
    var trusted by remember { mutableStateOf(vm.isTrusted(r)) }

    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { SummaryCard(r) }
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { share(ctx, r) }, modifier = Modifier.weight(1f)) { Text("مشاركة") }
                OutlinedButton(
                    onClick = { saver.launch("apk_report_${r.fileName.substringBeforeLast('.')}.txt") },
                    modifier = Modifier.weight(1f),
                ) { Text("حفظ") }
                OutlinedButton(onClick = onNew, modifier = Modifier.weight(1f)) { Text("ملف آخر") }
            }
        }
        if (r.behaviors.isNotEmpty()) {
            item { FindingsCard("🧬 سلوكيات تشبه برامج خبيثة معروفة", r.behaviors, Tone.BAD) }
        }
        item {
            if (r.dangers.isEmpty()) TextCard("⛔ علامات خطر", listOf("لا شيء ✔"), Tone.OK)
            else FindingsCard("⛔ علامات خطر", r.dangers, Tone.BAD)
        }
        item {
            if (r.mods.isEmpty()) TextCard("🔧 علامات تعديل", listOf("لا شيء، يبدو أصلياً ✔"), Tone.OK)
            else FindingsCard("🔧 علامات تعديل (ليست خطراً بحد ذاتها)", r.mods, Tone.WARN)
        }
        if (r.vulns.isNotEmpty()) item { VulnCard(r) }
        if (r.secrets.isNotEmpty()) {
            item {
                TextCard("🔑 أسرار مكتوبة داخل التطبيق", r.secrets.map { "${it.kind}: ${it.masked}" },
                    if (r.secrets.any { it.suspicious }) Tone.BAD else Tone.WARN, bullets = true)
            }
        }
        if (r.advice.isNotEmpty()) item { TextCard("💡 نصائح", r.advice, Tone.INFO, bullets = true) }
        if (r.unusualDomains.isNotEmpty()) {
            item {
                val shown = r.unusualDomains.take(40) +
                    if (r.unusualDomains.size > 40) listOf("... و${r.unusualDomains.size - 40} أخرى") else emptyList()
                TextCard("🌐 مواقع غير مألوفة في الكود (${r.unusualDomains.size})", shown, Tone.NORMAL)
            }
        }
        if (r.notes.isNotEmpty()) item { TextCard("ملاحظات", r.notes, Tone.MUTED, bullets = true) }
        if (r.packageName != null && r.signers.isNotEmpty()) {
            item {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("🔏 التوقيع الرسمي", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                        if (trusted) {
                            Text("هذا التوقيع محفوظ في قائمتك الموثوقة لـ ${r.packageName} ✔", color = StatusColors.ok())
                        } else {
                            Hint("إذا كان هذا الملف من مصدر رسمي (المطور أو Google Play)، احفظ توقيعه. أي نسخة لاحقة بتوقيع مختلف ستُكشف أنها ليست من المطور.")
                            OutlinedButton(onClick = { vm.trustSigner(r); trusted = true }) { Text("هذا ملف رسمي: احفظ توقيعه") }
                        }
                    }
                }
            }
        }
        item {
            Text(
                "التفاصيل (اضغط على أي قسم)",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 8.dp),
            )
        }
        itemsIndexed(r.sections) { i, sec ->
            SectionCard(sec, expanded[i] == true) { expanded[i] = expanded[i] != true }
        }
        item {
            Hint("تذكير: هذا فحص ثابت (لا يشغّل التطبيق)، ولا يوجد فحص يضمن الأمان 100%.")
        }
    }
}

@Composable
private fun SummaryCard(r: ScanResult) {
    val riskColor = when (r.level) {
        RiskLevel.LOW -> StatusColors.ok()
        RiskLevel.LOW_MEDIUM, RiskLevel.MEDIUM -> StatusColors.warn()
        RiskLevel.HIGH -> StatusColors.bad()
    }
    val modColor = if (r.isModified) StatusColors.warn() else StatusColors.ok()
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(r.fileName, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            r.packageName?.let { Hint(it) }
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                ScoreBox("درجة الخطر", r.riskScore, r.level.label, riskColor, Modifier.weight(1f))
                ScoreBox("درجة التعديل", r.modScore, if (r.isModified) "معدّل" else "أصلي على الأرجح", modColor, Modifier.weight(1f))
            }
            Spacer(Modifier.height(12.dp))
            Text(r.level.explanation, style = MaterialTheme.typography.bodyMedium)
            if (r.integrityVerified) Text("✔ التوقيع سليم: الملف لم يتغيّر بعد توقيعه", color = StatusColors.ok(), style = MaterialTheme.typography.bodySmall)
            if (r.vulns.isNotEmpty()) {
                val high = r.vulns.count { it.severity >= 3 }
                Text("🛡 ثغرات أمنية في التطبيق: ${r.vulns.size}" + if (high > 0) " ($high عالية)" else "",
                    color = if (high > 0) StatusColors.bad() else StatusColors.warn(), style = MaterialTheme.typography.bodySmall)
            }
            Hint("مدة الفحص: ${r.durationMs / 1000} ثانية")
        }
    }
}

@Composable
private fun ScoreBox(title: String, score: Int, label: String, color: Color, modifier: Modifier) {
    Column(
        modifier.border(1.dp, color, RoundedCornerShape(12.dp)).padding(12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(title, style = MaterialTheme.typography.labelMedium)
        Text("$score", fontSize = 36.sp, fontWeight = FontWeight.Bold, color = color)
        Text("من 100", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(label, style = MaterialTheme.typography.bodyMedium, color = color, textAlign = TextAlign.Center)
    }
}

@Composable
private fun FindingsCard(title: String, findings: List<Finding>, tone: Tone) {
    val color = StatusColors.forTone(tone)
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, color = color)
            SelectionContainer {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    findings.forEach { f ->
                        Row {
                            Text("[${f.weight}]", color = color, fontWeight = FontWeight.Bold, modifier = Modifier.width(44.dp))
                            Text(f.message, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun VulnCard(r: ScanResult) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("🛡 ثغرات تجعل التطبيق نفسه غير آمن", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Hint("هذه أخطاء أمنية في التطبيق (وليست سلوكاً خبيثاً)، لا تدخل في درجة الخطر.")
            SelectionContainer {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    r.vulns.forEach { v ->
                        val (label, tone) = when (v.severity) {
                            3 -> "عالية" to Tone.BAD
                            2 -> "متوسطة" to Tone.WARN
                            else -> "منخفضة" to Tone.MUTED
                        }
                        Column {
                            Text("[$label] ${v.title}", color = StatusColors.forTone(tone), style = MaterialTheme.typography.bodyMedium)
                            if (v.where.isNotEmpty()) Hint(v.where)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun TextCard(title: String, lines: List<String>, tone: Tone, bullets: Boolean = false) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            SelectionContainer {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    lines.forEach {
                        Text(
                            (if (bullets) "• " else "") + it,
                            style = MaterialTheme.typography.bodyMedium,
                            color = StatusColors.forTone(tone),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SectionCard(sec: Section, open: Boolean, onToggle: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth()) {
            Row(
                Modifier.fillMaxWidth().clickable(onClick = onToggle).padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(sec.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                Text(if (open) "▲" else "▼")
            }
            if (open) {
                HorizontalDivider()
                SelectionContainer {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        sec.lines.forEach { l ->
                            if (l.text.isEmpty()) {
                                Spacer(Modifier.height(4.dp))
                            } else {
                                Text(
                                    l.text,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = StatusColors.forTone(l.tone),
                                    fontWeight = if (l.tone == Tone.HEAD) FontWeight.Bold else null,
                                    modifier = Modifier.padding(start = (l.indent * 12).dp),
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------- خطأ ----------------
@Composable
private fun ErrorScreen(message: String, onBack: () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("تعذّر فحص الملف", style = MaterialTheme.typography.titleLarge, color = StatusColors.bad())
        Spacer(Modifier.height(12.dp))
        Text(message, textAlign = TextAlign.Center)
        Spacer(Modifier.height(24.dp))
        Button(onClick = onBack) { Text("رجوع") }
    }
}

private fun share(ctx: Context, r: ScanResult) {
    val text = r.toText().let { if (it.length > 200_000) it.take(200_000) + "\n..." else it }
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_SUBJECT, "تقرير فحص ${r.fileName}")
        putExtra(Intent.EXTRA_TEXT, text)
    }
    ctx.startActivity(Intent.createChooser(send, "مشاركة التقرير"))
}
