package io.github.mednouaoury.apksentry.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import io.github.mednouaoury.apksentry.core.Tone

private val Indigo = Color(0xFF1E3A8A)

@Composable
fun ApkSentryTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val ctx = LocalContext.current
    val scheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> darkColorScheme(primary = Color(0xFF9DB4FF))
        else -> lightColorScheme(primary = Indigo)
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

/** ألوان ثابتة للحالات (أخضر/برتقالي/أحمر) حتى تبقى واضحة مع أي ثيم. */
object StatusColors {
    @Composable
    fun ok() = if (isSystemInDarkTheme()) Color(0xFF81C784) else Color(0xFF2E7D32)

    @Composable
    fun warn() = if (isSystemInDarkTheme()) Color(0xFFFFB74D) else Color(0xFFB26A00)

    @Composable
    fun bad() = if (isSystemInDarkTheme()) Color(0xFFEF9A9A) else Color(0xFFC62828)

    @Composable
    fun info() = if (isSystemInDarkTheme()) Color(0xFF90CAF9) else Color(0xFF1565C0)

    @Composable
    fun forTone(t: Tone): Color = when (t) {
        Tone.OK -> ok()
        Tone.WARN -> warn()
        Tone.BAD -> bad()
        Tone.INFO -> info()
        Tone.MUTED -> MaterialTheme.colorScheme.onSurfaceVariant
        Tone.HEAD -> MaterialTheme.colorScheme.primary
        Tone.NORMAL -> MaterialTheme.colorScheme.onSurface
    }
}
