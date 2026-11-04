package io.github.mednouaoury.apksentry.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.mednouaoury.apksentry.core.Line
import io.github.mednouaoury.apksentry.core.ScanResult
import io.github.mednouaoury.apksentry.core.Tone

/** 2 = خطيرة (تُستعمل كثيراً في الفيروسات)، 1 = حساسة (خصوصيتك)، 0 = عادية. */
class PermInfo(val icon: ImageVector, val title: String, val explain: String, val level: Int)

/** شرح الصلاحيات بكلام بسيط. عدة صلاحيات تقنية قد تعني نفس الشيء للمستخدم، فنجمعها. */
object Permissions {
    private val TABLE: List<Pair<List<String>, PermInfo>> = listOf(
        listOf("BIND_ACCESSIBILITY_SERVICE") to PermInfo(AppIcons.Accessibility, "التحكم في الشاشة (خدمة الوصول)",
            "يرى كل ما يظهر على شاشتك ويستطيع الضغط والكتابة مكانك. أخطر صلاحية، وتعتمد عليها أغلب الفيروسات البنكية.", 2),
        listOf("READ_SMS", "RECEIVE_SMS", "SEND_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH") to PermInfo(AppIcons.Sms, "الرسائل SMS",
            "يقرأ أو يستقبل أو يرسل رسائلك، ومنها رموز التحقق التي يرسلها البنك.", 2),
        listOf("BIND_DEVICE_ADMIN") to PermInfo(AppIcons.Lock, "مدير الجهاز",
            "يستطيع قفل الهاتف أو مسح بياناته، ويصعب حذفه.", 2),
        listOf("SYSTEM_ALERT_WINDOW") to PermInfo(AppIcons.Layers, "الظهور فوق التطبيقات",
            "يستطيع رسم نافذة فوق تطبيق آخر، مثلاً صفحة دخول مزيّفة فوق تطبيق البنك.", 2),
        listOf("REQUEST_INSTALL_PACKAGES") to PermInfo(AppIcons.Download, "تثبيت تطبيقات أخرى",
            "يستطيع أن يطلب تثبيت تطبيقات جديدة، وهذا أسلوب الفيروسات التي تنزّل فيروسات أخرى.", 2),
        listOf("BIND_NOTIFICATION_LISTENER_SERVICE") to PermInfo(AppIcons.Bell, "قراءة إشعاراتك",
            "يرى كل الإشعارات التي تصلك، ومنها الرسائل ورموز التحقق.", 2),
        listOf("READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS") to PermInfo(AppIcons.Phone, "سجل المكالمات",
            "يرى من اتصلت بهم ومن اتصل بك.", 2),
        listOf("MANAGE_EXTERNAL_STORAGE") to PermInfo(AppIcons.Folder, "كل ملفاتك",
            "يصل إلى كل الملفات في هاتفك.", 2),
        listOf("ACCESS_BACKGROUND_LOCATION") to PermInfo(AppIcons.Location, "موقعك حتى وهو مغلق",
            "يعرف مكانك في أي وقت، حتى عندما لا تستعمله.", 2),
        listOf("CAMERA") to PermInfo(AppIcons.Camera, "الكاميرا", "يلتقط صوراً وفيديو.", 1),
        listOf("RECORD_AUDIO") to PermInfo(AppIcons.Mic, "الميكروفون", "يسجّل الصوت.", 1),
        listOf("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION") to PermInfo(AppIcons.Location, "موقعك", "يعرف مكانك.", 1),
        listOf("READ_CONTACTS", "WRITE_CONTACTS") to PermInfo(AppIcons.Person, "جهات الاتصال", "يرى أسماء وأرقام من تعرفهم.", 1),
        listOf("CALL_PHONE", "ANSWER_PHONE_CALLS") to PermInfo(AppIcons.Phone, "المكالمات", "يستطيع الاتصال أو الرد على المكالمات.", 1),
        listOf("READ_PHONE_STATE", "READ_PHONE_NUMBERS") to PermInfo(AppIcons.Phone, "معلومات الهاتف", "يعرف رقمك ومعلومات شريحتك.", 1),
        listOf("READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_VISUAL_USER_SELECTED") to PermInfo(AppIcons.Image, "صورك وفيديوهاتك", "يرى الصور والفيديوهات في هاتفك.", 1),
        listOf("READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_AUDIO") to PermInfo(AppIcons.Folder, "ملفاتك", "يقرأ أو يكتب ملفات في ذاكرة الهاتف.", 1),
        listOf("GET_ACCOUNTS", "READ_PROFILE") to PermInfo(AppIcons.Account, "حساباتك", "يرى الحسابات المسجّلة في هاتفك (Google وغيره).", 1),
        listOf("QUERY_ALL_PACKAGES") to PermInfo(AppIcons.Apps, "رؤية كل تطبيقاتك", "يعرف كل التطبيقات المثبتة عندك.", 1),
        listOf("PACKAGE_USAGE_STATS") to PermInfo(AppIcons.Eye, "مراقبة استخدامك", "يعرف أي تطبيق تستعمل ومتى.", 1),
        listOf("READ_CALENDAR", "WRITE_CALENDAR") to PermInfo(AppIcons.Calendar, "التقويم", "يرى مواعيدك.", 1),
        listOf("BODY_SENSORS", "BODY_SENSORS_BACKGROUND", "ACTIVITY_RECOGNITION") to PermInfo(AppIcons.Chip, "حساسات الجسم والحركة", "يعرف نشاطك البدني أو نبضك.", 1),
        listOf("INTERNET") to PermInfo(AppIcons.Globe, "الإنترنت", "يتصل بالإنترنت (أغلب التطبيقات تحتاجه).", 0),
        listOf("ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "CHANGE_WIFI_STATE", "CHANGE_NETWORK_STATE") to PermInfo(AppIcons.Wifi, "حالة الشبكة", "يعرف هل أنت متصل.", 0),
        listOf("BLUETOOTH", "BLUETOOTH_ADMIN", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN") to PermInfo(AppIcons.Bluetooth, "البلوتوث", "يتصل بأجهزة البلوتوث.", 0),
        listOf("NFC") to PermInfo(AppIcons.Nfc, "NFC", "يقرأ البطاقات والأجهزة القريبة جداً.", 0),
        listOf("RECEIVE_BOOT_COMPLETED") to PermInfo(AppIcons.Power, "يشتغل مع تشغيل الهاتف", "يبدأ تلقائياً عند تشغيل الهاتف.", 0),
        listOf("POST_NOTIFICATIONS") to PermInfo(AppIcons.Bell, "إرسال إشعارات", "يعرض لك إشعارات.", 0),
    )
    private val BY_NAME: Map<String, PermInfo> = TABLE.flatMap { (names, info) -> names.map { it to info } }.toMap()

    fun info(full: String): PermInfo? = BY_NAME[full.substringAfterLast('.')]

    /** الصلاحيات مجمّعة ومرتّبة من الأخطر. غير المعروفة نعدّها فقط. */
    fun group(perms: List<String>): Pair<List<PermInfo>, Int> {
        val known = LinkedHashMap<String, PermInfo>()
        var unknown = 0
        for (p in perms) {
            val i = info(p)
            if (i == null) unknown++ else known.putIfAbsent(i.title, i)
        }
        return known.values.sortedByDescending { it.level } to unknown
    }
}

/** الخلاصة بكلام بسيط: ماذا يعني هذا لك؟ وماذا تفعل؟ */
@Composable
fun SummaryCard(r: ScanResult, color: Color) {
    if (r.summary.isEmpty()) return
    SectionCard("ماذا يعني هذا لك؟", AppIcons.Info, color) {
        r.summary.forEach { SummaryLine(it) }
        if (r.action.isNotEmpty()) {
            Surface(shape = MaterialTheme.shapes.medium, color = color.copy(alpha = 0.14f), modifier = Modifier.fillMaxWidth()) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Icon(AppIcons.Shield, null, tint = color, modifier = Modifier.size(22.dp))
                    Text(r.action, style = MaterialTheme.typography.titleSmall, color = color)
                }
            }
        }
    }
}

@Composable
private fun SummaryLine(l: Line) {
    val (icon, c) = when (l.tone) {
        Tone.OK -> AppIcons.Check to StatusColors.ok()
        Tone.BAD -> AppIcons.Cancel to StatusColors.bad()
        Tone.WARN -> AppIcons.Info to StatusColors.warn()
        else -> AppIcons.Info to StatusColors.info()
    }
    Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Icon(icon, null, tint = c, modifier = Modifier.size(20.dp).padding(top = 1.dp))
        Text(l.text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
    }
}

/** الصلاحيات بأيقونات وشرح بسيط: الخطيرة أولاً، والعادية مطوية. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun PermissionsCard(perms: List<String>) {
    if (perms.isEmpty()) return
    val (groups, unknown) = remember(perms) { Permissions.group(perms) }
    val important = groups.filter { it.level > 0 }
    val normal = groups.filter { it.level == 0 }
    var showNormal by rememberSaveable { mutableStateOf(false) }
    val accent = when {
        important.any { it.level == 2 } -> StatusColors.bad()
        important.isNotEmpty() -> StatusColors.warn()
        else -> StatusColors.ok()
    }
    SectionCard("ماذا يستطيع أن يفعل في هاتفك؟", AppIcons.Lock, accent) {
        if (important.isEmpty()) Text("لا يطلب صلاحيات حساسة ✔", color = StatusColors.ok())
        important.forEach { PermRow(it) }
        if (normal.isNotEmpty() || unknown > 0) {
            val n = normal.size + unknown
            Text(
                (if (showNormal) "إخفاء" else "و $n صلاحيات عادية") + (if (showNormal) "" else "  ▾"),
                style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.clip(RoundedCornerShape(8.dp)).clickable { showNormal = !showNormal }.padding(vertical = 6.dp, horizontal = 4.dp),
            )
            AnimatedVisibility(showNormal) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        normal.forEach { p ->
                            Row(
                                Modifier.clip(RoundedCornerShape(50)).background(MaterialTheme.colorScheme.surfaceContainerHighest).padding(horizontal = 10.dp, vertical = 5.dp),
                                verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp),
                            ) {
                                Icon(p.icon, null, Modifier.size(15.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                                Text(p.title, style = MaterialTheme.typography.labelMedium)
                            }
                        }
                    }
                    if (unknown > 0) Hint("و $unknown صلاحيات تقنية أخرى (القائمة الكاملة في التفاصيل التقنية).")
                }
            }
        }
    }
}

@Composable
private fun PermRow(p: PermInfo) {
    val c = if (p.level == 2) StatusColors.bad() else StatusColors.warn()
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        IconBadge(p.icon, c, 40.dp)
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(p.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f, fill = false))
                if (p.level == 2) Pill("خطيرة", c)
            }
            Text(p.explain, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
