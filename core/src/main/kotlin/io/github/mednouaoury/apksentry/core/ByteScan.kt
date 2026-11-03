package io.github.mednouaoury.apksentry.core

/** يبحث داخل البايتات عن روابط ومواقع وعناوين IP وآثار برامج التعدين. */
class ByteScanner {
    val domains = sortedSetOf<String>()
    val ips = sortedSetOf<String>()
    val minerHits = linkedSetOf<String>()

    fun scan(buf: ByteArray, len: Int, where: String) {
        val end = minOf(len, buf.size)
        var i = 0
        while (i + 8 < end) {
            if (buf[i] == 'h'.code.toByte() && buf[i + 1] == 't'.code.toByte() &&
                buf[i + 2] == 't'.code.toByte() && buf[i + 3] == 'p'.code.toByte()
            ) {
                var j = i + 4
                if (j < end && buf[j] == 's'.code.toByte()) j++
                if (j + 3 <= end && buf[j] == ':'.code.toByte() && buf[j + 1] == '/'.code.toByte() && buf[j + 2] == '/'.code.toByte()) {
                    j += 3
                    var k = j
                    while (k < end && isHostChar(buf[k])) k++
                    if (k > j) {
                        val host = String(buf, j, k - j, Charsets.ISO_8859_1)
                        domainOf(host)?.let { if (!Rules.knownDomain(it)) domains.add(it) }
                        ipOf(host)?.let { if (!it.startsWith("127.") && !it.startsWith("0.") && !it.startsWith("10.") && !it.startsWith("192.168.")) ips.add(it) }
                    }
                    i = k
                    continue
                }
            }
            i++
        }
        for (m in Rules.MINER) {
            if (buf.indexOf(m, 0, end) >= 0) minerHits.add(where)
        }
    }

    companion object {
        private fun isHostChar(b: Byte): Boolean {
            val c = b.toInt()
            return (c in 'a'.code..'z'.code) || (c in 'A'.code..'Z'.code) || (c in '0'.code..'9'.code) || c == '.'.code || c == '-'.code
        }

        private fun isLetter(c: Char) = c in 'a'..'z' || c in 'A'..'Z'

        /** نفس سلوك التعبير ([A-Za-z0-9.-]+\.[A-Za-z]{2,}) في السكربت. */
        fun domainOf(run: String): String? {
            var k = run.length - 1
            while (k > 0) {
                if (run[k] == '.' && k + 2 < run.length + 1) {
                    var n = 0
                    while (k + 1 + n < run.length && isLetter(run[k + 1 + n])) n++
                    if (n >= 2) return run.substring(0, k + 1 + n).lowercase().trim('.').ifEmpty { null }
                }
                k--
            }
            return null
        }

        private val IP = Regex("^((?:\\d{1,3}\\.){3}\\d{1,3})")

        fun ipOf(run: String): String? = IP.find(run)?.groupValues?.get(1)

        private val URL_ANY = Regex("https?://[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")

        fun containsAnyUrl(s: String) = URL_ANY.containsMatchIn(s)
    }
}
