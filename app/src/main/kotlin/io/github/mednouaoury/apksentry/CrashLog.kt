package io.github.mednouaoury.apksentry

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * إذا توقّف التطبيق فجأة أثناء الفحص، نحفظ السبب لنعرضه في المرة القادمة،
 * حتى يرسله المستخدم ونصلح المشكل بدقة بدل التخمين.
 */
object CrashLog {
    private const val PREFS = "crashlog"
    private const val KEY_SCANNING = "scanning"
    private fun file(ctx: Context) = File(ctx.filesDir, "last_crash.txt")

    fun install(ctx: Context) {
        val app = ctx.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            runCatching {
                val sw = StringWriter()
                e.printStackTrace(PrintWriter(sw))
                val scanning = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_SCANNING, null)
                file(app).writeText(header(app) + "الملف: ${scanning ?: "-"}\nالخيط: ${t.name}\n\n" + sw.toString().take(20_000))
            }
            previous?.uncaughtException(t, e)
        }
    }

    private fun header(ctx: Context): String {
        val v = runCatching { ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName }.getOrNull()
        val rt = Runtime.getRuntime()
        return "ApkSentry $v\nAndroid ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) ${Build.MANUFACTURER} ${Build.MODEL}\n" +
            "الوقت: ${SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date())}\n" +
            "حد الذاكرة: ${rt.maxMemory() / (1024 * 1024)} ميجا\n"
    }

    fun scanStarted(ctx: Context, name: String) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY_SCANNING, name).commit()

    fun scanEnded(ctx: Context) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(KEY_SCANNING).apply()

    /** تقرير عن توقّف سابق (خطأ، أو قتل النظام للتطبيق أثناء الفحص)، أو null. */
    fun pendingReport(ctx: Context): String? {
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val scanning = prefs.getString(KEY_SCANNING, null)
        val crash = file(ctx).takeIf { it.exists() }?.readText()
        if (crash != null) return crash
        if (scanning == null) return null
        // الفحص لم ينتهِ ولم نسجّل خطأ: غالباً قتل النظامُ التطبيقَ (ذاكرة)
        var reason = "توقّف التطبيق أثناء الفحص بدون خطأ مسجّل (غالباً نفدت ذاكرة الهاتف)."
        if (Build.VERSION.SDK_INT >= 30) runCatching {
            val am = ctx.getSystemService(ActivityManager::class.java)
            am.getHistoricalProcessExitReasons(ctx.packageName, 0, 1).firstOrNull()?.let { info ->
                reason = when (info.reason) {
                    ApplicationExitInfo.REASON_LOW_MEMORY -> "النظام أوقف التطبيق لأن ذاكرة الهاتف نفدت."
                    ApplicationExitInfo.REASON_CRASH, ApplicationExitInfo.REASON_CRASH_NATIVE -> "خطأ داخلي في التطبيق."
                    ApplicationExitInfo.REASON_ANR -> "التطبيق توقّف عن الاستجابة."
                    ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE -> "النظام أوقف التطبيق لاستهلاكه موارد كثيرة."
                    else -> reason
                } + " (السبب ${info.reason}، الذاكرة المستعملة ${info.pss / 1024} ميجا)\n${info.description ?: ""}"
            }
        }
        return header(ctx) + "الملف: $scanning\n\n$reason"
    }

    fun clear(ctx: Context) {
        file(ctx).delete()
        scanEnded(ctx)
    }
}
