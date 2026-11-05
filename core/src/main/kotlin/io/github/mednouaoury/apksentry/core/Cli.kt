package io.github.mednouaoury.apksentry.core

import java.io.File
import java.io.PrintStream

/**
 * نسخة سطر الأوامر للحاسوب:
 *   java -jar apksentry-cli.jar <ملف> [--vt مفتاح] [--expect بصمة] [--out تقرير.txt]
 */
object Cli {
    @JvmStatic
    fun main(args: Array<String>) {
        val out = PrintStream(System.out, true, "UTF-8")
        val err = PrintStream(System.err, true, "UTF-8")
        var path: String? = null
        var key: String? = null
        var mbKey: String? = null
        var trustFile: String? = null
        var noFlow = false
        var noRep = false
        var debug = false
        var simFile: String? = null
        var expect: String? = null
        var report: String? = null
        var i = 0
        while (i < args.size) {
            when (args[i]) {
                "--vt" -> key = args.getOrNull(++i)
                "--mb" -> mbKey = args.getOrNull(++i)
                "--trusted" -> trustFile = args.getOrNull(++i)
                "--no-flow" -> noFlow = true
                "--no-reputation" -> noRep = true
                "--debug" -> debug = true
                "--tlsh-db" -> simFile = args.getOrNull(++i)
                "--expect" -> expect = args.getOrNull(++i)
                "--out" -> report = args.getOrNull(++i)
                else -> path = args[i]
            }
            i++
        }
        if (path == null) {
            err.println("الاستعمال: apksentry <ملف APK/APKS/XAPK> [--vt مفتاح] [--mb مفتاح_MalwareBazaar] [--expect بصمة]")
            err.println("          [--trusted ملف_الشهادات.txt] [--tlsh-db قاعدة_البصمات.csv] [--no-flow] [--out تقرير.txt]")
            err.println("ملف الشهادات: كل سطر = اسم_الحزمة بصمة_SHA256")
            System.exit(2)
        }
        val f = File(path)
        var last = ""
        val trusted = trustFile?.let { tf ->
            File(tf).readLines().mapNotNull { l ->
                val p = l.trim().split(Regex("\\s+"))
                if (p.size >= 2 && !l.trim().startsWith("#")) p[0] to p[1].lowercase().replace(":", "") else null
            }
        } ?: emptyList()
        val options = ScanOptions(
            virusTotalKey = key,
            malwareBazaarKey = mbKey,
            expectedCert = expect,
            officialCerts = { pkg -> trusted.filter { it.first == pkg }.map { OfficialCert(it.second, "قائمتك الموثوقة") } },
            dataFlow = !noFlow,
            reputation = !noRep,
            debug = debug,
            similarity = simFile?.let { SimilarityDb.parse(File(it).readText()) } ?: SimilarityDb.EMPTY,
        )
        val scanner = Scanner(options, { msg, frac ->
            val line = "[${frac?.let { (it * 100).toInt() } ?: 0}%] $msg"
            if (line != last) { err.println(line); last = line }
        })
        val res = try {
            FileChannelSource.open(f).use { scanner.scan(it, f.name) }
        } catch (e: Exception) {
            err.println("خطأ: ${e.javaClass.simpleName}: ${e.message}")
            System.exit(3)
            return
        }
        val text = res.toText()
        out.print(text)
        // تناقضات في التقرير (يجمعها القياس ويفشل بسببها)
        for (c in Consistency.check(res)) out.println("CONTRADICTION: $c")
        if (report != null) File(report).writeText(text, Charsets.UTF_8)
        err.println("المدة: ${res.durationMs / 1000.0} ثانية")
    }
}
