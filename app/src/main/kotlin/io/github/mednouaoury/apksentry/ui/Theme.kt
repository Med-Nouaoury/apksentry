package io.github.mednouaoury.apksentry.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.mednouaoury.apksentry.R
import io.github.mednouaoury.apksentry.core.Tone

/** هوية ApkSentry: أزرق أمني مع لمسة فيروزية، وخلفية داكنة عميقة. */
object Brand {
    val Blue = Color(0xFF3B82F6)
    val BlueLight = Color(0xFF8AB4FF)
    val Teal = Color(0xFF14B8A6)
    val TealLight = Color(0xFF5EEAD4)
    val Navy = Color(0xFF0A1020)
    val NavySurface = Color(0xFF111A2E)
    val NavyHigh = Color(0xFF18233B)
    val NavyHigher = Color(0xFF1F2C48)
}

val PlexArabic = FontFamily(
    Font(R.font.plex_arabic_regular, FontWeight.Normal),
    Font(R.font.plex_arabic_medium, FontWeight.Medium),
    Font(R.font.plex_arabic_semibold, FontWeight.SemiBold),
    Font(R.font.plex_arabic_bold, FontWeight.Bold),
)

private val DarkScheme = darkColorScheme(
    primary = Brand.BlueLight,
    onPrimary = Color(0xFF06142E),
    primaryContainer = Color(0xFF1D3A6E),
    onPrimaryContainer = Color(0xFFDCE7FF),
    secondary = Brand.TealLight,
    onSecondary = Color(0xFF00201C),
    secondaryContainer = Color(0xFF0F3D38),
    onSecondaryContainer = Color(0xFFC8FFF4),
    background = Brand.Navy,
    onBackground = Color(0xFFE6EAF2),
    surface = Brand.Navy,
    onSurface = Color(0xFFE6EAF2),
    surfaceVariant = Brand.NavyHigh,
    onSurfaceVariant = Color(0xFF9AA6BF),
    surfaceContainerLowest = Color(0xFF070C18),
    surfaceContainerLow = Brand.NavySurface,
    surfaceContainer = Brand.NavySurface,
    surfaceContainerHigh = Brand.NavyHigh,
    surfaceContainerHighest = Brand.NavyHigher,
    outline = Color(0xFF34415E),
    outlineVariant = Color(0xFF243049),
    error = Color(0xFFFF8A80),
)

private val LightScheme = lightColorScheme(
    primary = Color(0xFF2563EB),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFDCE7FF),
    onPrimaryContainer = Color(0xFF0B2A66),
    secondary = Color(0xFF0D9488),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFCCF5EE),
    onSecondaryContainer = Color(0xFF053B35),
    background = Color(0xFFF4F6FB),
    onBackground = Color(0xFF0F172A),
    surface = Color(0xFFF4F6FB),
    onSurface = Color(0xFF0F172A),
    surfaceVariant = Color(0xFFE7ECF5),
    onSurfaceVariant = Color(0xFF5B6478),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color.White,
    surfaceContainer = Color.White,
    surfaceContainerHigh = Color(0xFFF0F3FA),
    surfaceContainerHighest = Color(0xFFE7ECF5),
    outline = Color(0xFFC3CBDA),
    outlineVariant = Color(0xFFDDE3EE),
)

private fun TextStyle.plex() = copy(fontFamily = PlexArabic)

private val AppTypography = Typography().let { t ->
    Typography(
        displayLarge = t.displayLarge.plex(), displayMedium = t.displayMedium.plex(), displaySmall = t.displaySmall.plex(),
        headlineLarge = t.headlineLarge.plex().copy(fontWeight = FontWeight.Bold),
        headlineMedium = t.headlineMedium.plex().copy(fontWeight = FontWeight.Bold),
        headlineSmall = t.headlineSmall.plex().copy(fontWeight = FontWeight.Bold),
        titleLarge = t.titleLarge.plex().copy(fontWeight = FontWeight.Bold),
        titleMedium = t.titleMedium.plex().copy(fontWeight = FontWeight.SemiBold),
        titleSmall = t.titleSmall.plex().copy(fontWeight = FontWeight.SemiBold),
        bodyLarge = t.bodyLarge.plex(), bodyMedium = t.bodyMedium.plex(), bodySmall = t.bodySmall.plex(),
        labelLarge = t.labelLarge.plex().copy(fontWeight = FontWeight.SemiBold),
        labelMedium = t.labelMedium.plex(), labelSmall = t.labelSmall.plex(),
    )
}

private val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(18.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(32.dp),
)

@Composable
fun ApkSentryTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkScheme else LightScheme,
        typography = AppTypography,
        shapes = AppShapes,
        content = content,
    )
}

/** ألوان الحالات (آمن / تحذير / خطر / معلومة) ثابتة مع أي ثيم. */
object StatusColors {
    @Composable fun ok() = if (isSystemInDarkTheme()) Color(0xFF4ADE80) else Color(0xFF16A34A)
    @Composable fun warn() = if (isSystemInDarkTheme()) Color(0xFFFBBF24) else Color(0xFFD97706)
    @Composable fun bad() = if (isSystemInDarkTheme()) Color(0xFFF87171) else Color(0xFFDC2626)
    @Composable fun info() = if (isSystemInDarkTheme()) Color(0xFF7DD3FC) else Color(0xFF0284C7)

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
