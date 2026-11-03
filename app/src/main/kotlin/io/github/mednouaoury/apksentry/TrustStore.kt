package io.github.mednouaoury.apksentry

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import io.github.mednouaoury.apksentry.core.OfficialCert
import java.security.MessageDigest

/**
 * مصادر الشهادات الرسمية:
 * 1) النسخة المثبتة على الهاتف إذا كانت من Google Play (الأندرويد يعرف شهادتها).
 * 2) قائمة يحفظها المستعمل عندما يفحص ملفاً من مصدر رسمي.
 */
class TrustStore(private val ctx: Context) {
    private val prefs = ctx.getSharedPreferences("trusted_signers", Context.MODE_PRIVATE)

    fun get(pkg: String): Set<String> =
        prefs.getString(pkg, null)?.split(',')?.filter { it.isNotBlank() }?.toSet() ?: emptySet()

    fun add(pkg: String, fingerprints: List<String>) {
        val all = get(pkg) + fingerprints.map { it.lowercase() }
        prefs.edit().putString(pkg, all.joinToString(",")).apply()
    }

    fun officialCerts(pkg: String): List<OfficialCert> {
        val out = ArrayList<OfficialCert>()
        get(pkg).forEach { out.add(OfficialCert(it, "قائمتك الموثوقة")) }
        out.addAll(fromInstalledPlayApp(pkg))
        return out
    }

    /** لا نعتمد النسخة المثبتة إلا إذا ثبّتها Google Play، لأنها قد تكون هي نفسها النسخة المعدّلة. */
    private fun fromInstalledPlayApp(pkg: String): List<OfficialCert> = try {
        val pm = ctx.packageManager
        val installer = if (Build.VERSION.SDK_INT >= 30) {
            pm.getInstallSourceInfo(pkg).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(pkg)
        }
        if (installer != "com.android.vending") {
            emptyList()
        } else {
            val certs: List<ByteArray> = if (Build.VERSION.SDK_INT >= 28) {
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                val si = info.signingInfo
                when {
                    si == null -> emptyList()
                    si.hasMultipleSigners() -> si.apkContentsSigners.map { it.toByteArray() }
                    else -> si.signingCertificateHistory.map { it.toByteArray() }
                }
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                info.signatures?.map { it.toByteArray() } ?: emptyList()
            }
            certs.map { OfficialCert(sha256(it), "النسخة الرسمية المثبتة من Google Play") }
        }
    } catch (e: Exception) {
        emptyList()
    }

    private fun sha256(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
