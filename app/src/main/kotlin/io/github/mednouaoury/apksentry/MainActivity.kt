package io.github.mednouaoury.apksentry

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.core.content.IntentCompat
import io.github.mednouaoury.apksentry.ui.ApkSentryApp
import io.github.mednouaoury.apksentry.ui.ApkSentryTheme

class MainActivity : ComponentActivity() {
    private val vm: ScanViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        CrashLog.install(this)
        enableEdgeToEdge()
        if (savedInstanceState == null) showCrashReport()
        // إذا كانت هناك تطبيقات محظورة والجدار متوقف (مثلاً قتله النظام)، نعيد تشغيله
        io.github.mednouaoury.apksentry.net.Firewall.load(this)
        if (savedInstanceState == null && io.github.mednouaoury.apksentry.net.Firewall.blocked.value.isNotEmpty() &&
            !io.github.mednouaoury.apksentry.net.Firewall.running.value && io.github.mednouaoury.apksentry.net.Firewall.canStartSilently(this)
        ) runCatching { io.github.mednouaoury.apksentry.net.NetMonitorService.refresh(this) }
        if (savedInstanceState == null) handleIntent(intent)
        addOnNewIntentListener { handleIntent(it) }
        setContent {
            ApkSentryTheme {
                // الواجهة عربية، فنجعل الاتجاه من اليمين لليسار دائماً
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                    ApkSentryApp(vm)
                }
            }
        }
    }

    /** إذا توقّف التطبيق في المرة الماضية أثناء الفحص: نعرض السبب ليرسله المستخدم. */
    private fun showCrashReport() {
        val report = CrashLog.pendingReport(this) ?: return
        CrashLog.clear(this)
        android.app.AlertDialog.Builder(this)
            .setTitle("توقّف التطبيق في المرة الماضية")
            .setMessage("نعتذر. هذا التقرير يساعدنا على إصلاح المشكل (لا يحتوي بياناتك):\n\n" + report.take(1500))
            .setPositiveButton("مشاركة التقرير") { _, _ ->
                runCatching {
                    startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_TEXT, report)
                    }, "مشاركة التقرير"))
                }
            }
            .setNegativeButton("حسناً", null)
            .show()
    }

    /** عند "فتح بواسطة" أو "مشاركة" ملف من مدير الملفات. */
    private fun handleIntent(intent: Intent?) {
        val uri: Uri? = when (intent?.action) {
            Intent.ACTION_VIEW -> intent.data
            Intent.ACTION_SEND -> IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
            else -> null
        }
        if (uri != null) vm.scan(uri)
    }
}
