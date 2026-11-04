package io.github.mednouaoury.apksentry

import android.app.Application
import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.mednouaoury.apksentry.core.ByteSource
import io.github.mednouaoury.apksentry.core.FileChannelSource
import io.github.mednouaoury.apksentry.core.MalwareBazaarFeed
import io.github.mednouaoury.apksentry.core.SimilarityDb
import io.github.mednouaoury.apksentry.core.ScanCancelledException
import io.github.mednouaoury.apksentry.core.ScanOptions
import io.github.mednouaoury.apksentry.core.ScanResult
import io.github.mednouaoury.apksentry.core.Scanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.io.IOException

sealed interface UiState {
    data object Idle : UiState
    data class Scanning(val fileName: String, val message: String, val fraction: Float) : UiState
    class Done(val result: ScanResult) : UiState
    data class Failed(val message: String) : UiState
}

class ScanViewModel(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("settings", Context.MODE_PRIVATE)

    private val _state = MutableStateFlow<UiState>(UiState.Idle)
    val state: StateFlow<UiState> = _state.asStateFlow()

    var vtKey by mutableStateOf(prefs.getString("vt_key", "") ?: "")
        private set
    var expectedCert by mutableStateOf(prefs.getString("expected_cert", "") ?: "")
        private set
    var mbKey by mutableStateOf(prefs.getString("mb_key", "") ?: "")
        private set
    var dataFlow by mutableStateOf(prefs.getBoolean("data_flow", true))
        private set

    private val trust = TrustStore(app)

    // ---- قاعدة البصمات التقريبية (TLSH) للفيروسات المعروفة، محفوظة على الهاتف ----
    private val simFile = File(app.filesDir, "malware_tlsh.csv")
    @Volatile
    private var simDb: SimilarityDb? = null
    var simCount by mutableStateOf(prefs.getInt("sim_count", 0))
        private set
    var simUpdatedAt by mutableStateOf(prefs.getLong("sim_updated", 0L))
        private set
    var simBusy by mutableStateOf(false)
        private set
    var simMessage by mutableStateOf<String?>(null)
        private set

    init {
        // تحديث تلقائي كل أسبوع (إذا كان المفتاح موجوداً)
        if (mbKey.isNotBlank() && System.currentTimeMillis() - simUpdatedAt > 7L * 24 * 3600 * 1000) updateSimilarityDb()
    }

    private fun loadSimDb(): SimilarityDb {
        simDb?.let { return it }
        val db = try {
            if (simFile.exists()) SimilarityDb.parse(simFile.readText()) else SimilarityDb.EMPTY
        } catch (e: Exception) {
            SimilarityDb.EMPTY
        }
        simDb = db
        return db
    }

    /** نجلب أحدث 1000 فيروس أندرويد من MalwareBazaar ونضيفهم للقاعدة المحفوظة. */
    fun updateSimilarityDb() {
        if (simBusy) return
        val key = mbKey
        if (key.isBlank()) {
            simMessage = "أدخل مفتاح MalwareBazaar أولاً"
            return
        }
        simBusy = true
        simMessage = "جاري التحميل..."
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val old = loadSimDb()
                val fresh = MalwareBazaarFeed.recentApks(key)
                val merged = old.merge(fresh)
                val tmp = File(simFile.path + ".tmp")
                tmp.writeText(merged.serialize())
                if (!tmp.renameTo(simFile)) { simFile.delete(); tmp.renameTo(simFile) }
                simDb = merged
                val added = merged.size - old.size
                val now = System.currentTimeMillis()
                prefs.edit().putInt("sim_count", merged.size).putLong("sim_updated", now).apply()
                simCount = merged.size
                simUpdatedAt = now
                simMessage = "تمت إضافة $added فيروس جديد ✔"
            } catch (e: Exception) {
                simMessage = "فشل التحديث: ${e.message ?: e.javaClass.simpleName}"
            } finally {
                simBusy = false
            }
        }
    }

    @Volatile
    private var cancelled = false
    private var job: Job? = null

    fun updateVtKey(v: String) {
        vtKey = v.trim()
        prefs.edit().putString("vt_key", vtKey).apply()
    }

    fun updateMbKey(v: String) {
        mbKey = v.trim()
        prefs.edit().putString("mb_key", mbKey).apply()
    }

    fun updateDataFlow(v: Boolean) {
        dataFlow = v
        prefs.edit().putBoolean("data_flow", v).apply()
    }

    /** المستعمل يؤكد أن هذا الملف من مصدر رسمي: نحفظ توقيعه للمقارنة لاحقاً. */
    fun trustSigner(result: ScanResult) {
        val pkg = result.packageName ?: return
        trust.add(pkg, result.signers)
    }

    fun isTrusted(result: ScanResult): Boolean {
        val pkg = result.packageName ?: return false
        return result.signers.isNotEmpty() && trust.get(pkg).containsAll(result.signers)
    }

    fun updateExpectedCert(v: String) {
        expectedCert = v.trim()
        prefs.edit().putString("expected_cert", expectedCert).apply()
    }

    fun cancel() {
        cancelled = true
    }

    fun reset() {
        if (job?.isActive != true) _state.value = UiState.Idle
    }

    fun scan(uri: Uri) {
        if (job?.isActive == true) return
        cancelled = false
        val ctx = getApplication<Application>()
        val name = displayName(ctx, uri) ?: uri.lastPathSegment ?: "file.apk"
        _state.value = UiState.Scanning(name, "فتح الملف...", 0f)
        job = viewModelScope.launch(Dispatchers.IO) {
            var copy: File? = null
            try {
                val opened = openSource(ctx, uri, name)
                copy = opened.second
                val options = ScanOptions(
                    virusTotalKey = vtKey.ifBlank { null },
                    malwareBazaarKey = mbKey.ifBlank { null },
                    expectedCert = expectedCert.ifBlank { null },
                    officialCerts = { pkg -> trust.officialCerts(pkg) },
                    tempDir = ctx.cacheDir,
                    dataFlow = dataFlow,
                    similarity = loadSimDb(),
                )
                var lastUpdate = 0L
                val scanner = Scanner(options, { msg, fraction ->
                    val now = System.currentTimeMillis()
                    if (now - lastUpdate > 100) {
                        lastUpdate = now
                        _state.value = UiState.Scanning(name, msg, fraction ?: 0f)
                    }
                }, { cancelled })
                CrashLog.scanStarted(ctx, name)
                val result = opened.first.use { src -> onBigStack { scanner.scan(src, name) } }
                _state.value = UiState.Done(result)
            } catch (e: ScanCancelledException) {
                _state.value = UiState.Idle
            } catch (e: OutOfMemoryError) {
                _state.value = UiState.Failed("ذاكرة الهاتف لا تكفي لفحص هذا الملف. جرّب نسخة الحاسوب.")
            } catch (e: StackOverflowError) {
                _state.value = UiState.Failed("بنية هذا الملف معقّدة جداً (أو مُعدّة لإسقاط أدوات الفحص).")
            } catch (e: Throwable) {
                _state.value = UiState.Failed(e.message ?: e.javaClass.simpleName)
            } finally {
                CrashLog.scanEnded(ctx)
                copy?.delete()
            }
        }
    }

    /**
     * نفتح الملف بقراءة عشوائية مباشرة إن أمكن (بدون نسخ).
     * بعض المصادر (مثل Google Drive) لا تسمح بذلك، فننسخ الملف أولاً.
     */
    private fun openSource(ctx: Context, uri: Uri, name: String): Pair<ByteSource, File?> {
        val pfd = ctx.contentResolver.openFileDescriptor(uri, "r") ?: throw IOException("تعذّر فتح الملف")
        // AutoCloseInputStream يغلق الملف عبر pfd نفسه (أسلم مع fdsan في الأندرويد الحديث)
        val fis = ParcelFileDescriptor.AutoCloseInputStream(pfd)
        val channel = fis.channel
        val seekable = try {
            channel.position(0)
            channel.size() > 0
        } catch (e: Exception) {
            false
        }
        if (seekable) {
            return FileChannelSource(channel, fis) to null
        }
        fis.close()
        val tmp = File(ctx.cacheDir, "picked_${System.currentTimeMillis()}.bin")
        val input = ctx.contentResolver.openInputStream(uri) ?: throw IOException("تعذّر فتح الملف")
        try {
            input.use { i ->
                tmp.outputStream().use { o ->
                    val buf = ByteArray(1 shl 20)
                    var done = 0L
                    while (true) {
                        if (cancelled) throw ScanCancelledException()
                        val r = i.read(buf)
                        if (r < 0) break
                        o.write(buf, 0, r)
                        done += r
                        _state.value = UiState.Scanning(name, "نسخ الملف: ${done / (1024 * 1024)} ميجا", 0f)
                    }
                }
            }
        } catch (t: Throwable) {
            tmp.delete()
            throw t
        }
        return FileChannelSource.open(tmp) to tmp
    }

    private fun displayName(ctx: Context, uri: Uri): String? = try {
        ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    } catch (e: Exception) {
        null
    }
}

/**
 * المحاكيات تستدعي نفسها بعمق (Java ↔ native)، ومكدّس الخيوط العادية في أندرويد صغير.
 * نشغّل الفحص في خيط بمكدّس كبير، وننقل أي خطأ كما هو إلى المستدعي.
 */
private fun <T> onBigStack(block: () -> T): T {
    var result: Result<T>? = null
    val t = Thread(null, { result = runCatching(block) }, "apksentry-scan", 64L * 1024 * 1024)
    t.start()
    t.join()
    return result!!.getOrThrow()
}
