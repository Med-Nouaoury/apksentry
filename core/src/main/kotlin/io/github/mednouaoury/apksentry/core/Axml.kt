package io.github.mednouaoury.apksentry.core

/** عنصر من ملف AndroidManifest.xml بعد فك ترميزه. */
class XmlElement(val tag: String, val attrs: Map<String, String>, val parent: XmlElement?) {
    val children = ArrayList<XmlElement>()

    fun attr(name: String): String? = attrs[name]

    fun walk(): Sequence<XmlElement> = sequence {
        yield(this@XmlElement)
        for (c in children) yieldAll(c.walk())
    }
}

/** قارئ لصيغة XML الثنائية التي يستعملها الأندرويد (AXML). */
object Axml {
    private const val RES_STRING_POOL = 0x0001
    private const val RES_XML = 0x0003
    private const val RES_XML_START_ELEMENT = 0x0102
    private const val RES_XML_END_ELEMENT = 0x0103
    private const val RES_XML_RESOURCE_MAP = 0x0180

    /** أسماء بعض الخصائص حسب رقمها، لأن بعض التطبيقات تحذف الأسماء لتعقيد القراءة. */
    private val ATTR_IDS = mapOf(
        0x01010003 to "name",
        0x01010010 to "exported",
        0x0101000f to "debuggable",
        0x01010006 to "permission",
        0x010104ec to "usesCleartextTraffic",
        0x0101021b to "versionCode",
        0x0101021c to "versionName",
        0x0101020c to "minSdkVersion",
        0x01010270 to "targetSdkVersion",
    )

    fun parse(data: ByteArray): XmlElement? {
        if (data.size < 8 || data.u16(0) != RES_XML) return null
        var strings: Array<String> = emptyArray()
        var resIds = IntArray(0)
        var root: XmlElement? = null
        var current: XmlElement? = null
        var p = data.u16(2)
        while (p + 8 <= data.size) {
            val type = data.u16(p)
            val headerSize = data.u16(p + 2)
            val chunkSize = data.i32(p + 4)
            if (chunkSize < 8 || p + chunkSize > data.size) break
            when (type) {
                RES_STRING_POOL -> strings = readStringPool(data, p)
                RES_XML_RESOURCE_MAP -> {
                    val n = (chunkSize - headerSize) / 4
                    resIds = IntArray(n) { data.i32(p + headerSize + it * 4) }
                }
                RES_XML_START_ELEMENT -> {
                    val ext = p + headerSize
                    val tag = strings.getOrElse(data.i32(ext + 4)) { "?" }
                    val attrStart = data.u16(ext + 8)
                    val attrSize = data.u16(ext + 10).let { if (it == 0) 20 else it }
                    val attrCount = data.u16(ext + 12)
                    val attrs = LinkedHashMap<String, String>()
                    for (i in 0 until attrCount) {
                        val a = ext + attrStart + i * attrSize
                        if (a + 20 > data.size) break
                        val nameIdx = data.i32(a + 4)
                        var name = strings.getOrElse(nameIdx) { "" }
                        if (name.isEmpty() && nameIdx in resIds.indices) name = ATTR_IDS[resIds[nameIdx]] ?: ""
                        if (name.isEmpty()) continue
                        val raw = data.i32(a + 8)
                        val dataType = data.u8(a + 15)
                        val value = data.i32(a + 16)
                        attrs[name] = when {
                            raw >= 0 && raw < strings.size -> strings[raw]
                            dataType == 0x03 -> strings.getOrElse(value) { "" }
                            dataType == 0x12 -> if (value != 0) "true" else "false"
                            dataType == 0x10 -> value.toString()
                            dataType == 0x11 -> "0x" + Integer.toHexString(value)
                            dataType == 0x01 -> "@0x" + Integer.toHexString(value)
                            else -> value.toString()
                        }
                    }
                    val el = XmlElement(tag, attrs, current)
                    if (current == null) { if (root == null) root = el } else current.children.add(el)
                    current = el
                }
                RES_XML_END_ELEMENT -> current = current?.parent
            }
            p += chunkSize
        }
        return root
    }

    internal fun readStringPool(d: ByteArray, p: Int): Array<String> {
        val headerSize = d.u16(p + 2)
        val count = d.i32(p + 8)
        val flags = d.i32(p + 16)
        val stringsStart = d.i32(p + 20)
        val utf8 = flags and 0x100 != 0
        if (count < 0 || count > 1_000_000) return emptyArray()
        return Array(count) { i ->
            try {
                val off = p + stringsStart + d.i32(p + headerSize + i * 4)
                if (utf8) readUtf8(d, off) else readUtf16(d, off)
            } catch (e: Exception) {
                ""
            }
        }
    }

    private fun readUtf8(d: ByteArray, o: Int): String {
        var q = o
        // طول UTF-16 (نتجاهله) ثم طول UTF-8
        q += if (d.u8(q) and 0x80 != 0) 2 else 1
        val len: Int
        if (d.u8(q) and 0x80 != 0) {
            len = ((d.u8(q) and 0x7f) shl 8) or d.u8(q + 1); q += 2
        } else {
            len = d.u8(q); q += 1
        }
        return String(d, q, minOf(len, d.size - q), Charsets.UTF_8)
    }

    private fun readUtf16(d: ByteArray, o: Int): String {
        var q = o
        var len = d.u16(q); q += 2
        if (len and 0x8000 != 0) {
            len = ((len and 0x7fff) shl 16) or d.u16(q); q += 2
        }
        val n = minOf(len, (d.size - q) / 2)
        val chars = CharArray(n) { d.u16(q + it * 2).toChar() }
        return String(chars)
    }
}
