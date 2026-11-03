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
        enableEdgeToEdge()
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
