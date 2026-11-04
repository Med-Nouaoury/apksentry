package io.github.mednouaoury.apksentry.core

import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

class ZipEntryInfo(
    val name: String,
    val method: Int,
    val compressedSize: Long,
    val size: Long,
    internal val localHeaderOffset: Long,
    val flags: Int = 0,
) {
    val isDirectory get() = name.endsWith("/")
    /**
     * الأندرويد كيقرا أي طريقة ضغط غير deflate كأنها بلا ضغط. الفيروسات كتستغل هادشي:
     * كتحط رقم طريقة مزيّف باش أدوات الفحص تطيح، والأندرويد كيثبّت التطبيق عادي.
     */
    val isStored get() = method != 8
    /** طريقة ضغط غير موجودة (حيلة ضد التحليل). */
    val fakeMethod get() = method != 0 && method != 8
    /** علامة "مشفّر" مزيّفة: الأندرويد كيتجاهلها، والأدوات كترفض الملف. */
    val fakeEncrypted get() = flags and 1 != 0
    /** الحجم الحقيقي للبيانات المخزّنة بلا ضغط. */
    internal val storedLength get() = if (method == 0) size else compressedSize
}

/**
 * قارئ ZIP بسيط يقرأ الفهرس المركزي فقط، يدعم ZIP64 (ملفات أكبر من 4 جيجا)،
 * ولا يحمّل الملفات إلى الذاكرة إلا عند الطلب.
 */
class ZipArchive(val src: ByteSource) {
    val entries: List<ZipEntryInfo>
    val centralDirOffset: Long
    /** موقع نهاية الفهرس (EOCD). */
    val eocdOffset: Long
    private val byName: Map<String, ZipEntryInfo>

    init {
        val tailLen = minOf(src.size, 65_557L).toInt()
        if (tailLen < 22) throw IOException("ليس ملف ZIP")
        val tailStart = src.size - tailLen
        val tail = src.readFully(tailStart, tailLen)
        var eocd = -1
        for (i in tailLen - 22 downTo 0) {
            if (tail.u32(i) == 0x06054b50L) { eocd = i; break }
        }
        if (eocd < 0) throw IOException("ليس ملف ZIP (لم نجد نهاية الفهرس)")
        eocdOffset = tailStart + eocd
        var count = tail.u16(eocd + 10).toLong()
        var cdSize = tail.u32(eocd + 12)
        var cdOff = tail.u32(eocd + 16)
        if (count == 0xffffL || cdSize == 0xffffffffL || cdOff == 0xffffffffL) {
            val locPos = tailStart + eocd - 20
            if (locPos >= 0) {
                val loc = src.readFully(locPos, 20)
                if (loc.u32(0) == 0x07064b50L) {
                    val z64 = src.readFully(loc.u64(8), 56)
                    if (z64.u32(0) == 0x06064b50L) {
                        count = z64.u64(32)
                        cdSize = z64.u64(40)
                        cdOff = z64.u64(48)
                    }
                }
            }
        }
        if (cdSize > 256L * 1024 * 1024 || cdOff + cdSize > src.size) throw IOException("فهرس ZIP غير صالح")
        centralDirOffset = cdOff
        val cd = src.readFully(cdOff, cdSize.toInt())
        val list = ArrayList<ZipEntryInfo>(minOf(count, 200_000L).toInt())
        var p = 0
        while (p + 46 <= cd.size && cd.u32(p) == 0x02014b50L) {
            val flags = cd.u16(p + 8)
            val method = cd.u16(p + 10)
            var comp = cd.u32(p + 20)
            var uncomp = cd.u32(p + 24)
            val nameLen = cd.u16(p + 28)
            val extraLen = cd.u16(p + 30)
            val commentLen = cd.u16(p + 32)
            var lho = cd.u32(p + 42)
            val name = String(cd, p + 46, nameLen, if (flags and 0x800 != 0) Charsets.UTF_8 else Charsets.UTF_8)
            // حقل ZIP64 الإضافي
            var e = p + 46 + nameLen
            val eEnd = minOf(e + extraLen, cd.size)
            while (e + 4 <= eEnd) {
                val id = cd.u16(e)
                val sz = cd.u16(e + 2)
                if (id == 0x0001) {
                    var q = e + 4
                    if (uncomp == 0xffffffffL && q + 8 <= eEnd) { uncomp = cd.u64(q); q += 8 }
                    if (comp == 0xffffffffL && q + 8 <= eEnd) { comp = cd.u64(q); q += 8 }
                    if (lho == 0xffffffffL && q + 8 <= eEnd) { lho = cd.u64(q) }
                }
                e += 4 + sz
            }
            list.add(ZipEntryInfo(name, method, comp, uncomp, lho, flags))
            p += 46 + nameLen + extraLen + commentLen
        }
        entries = list
        byName = list.associateBy { it.name }
    }

    fun entry(name: String): ZipEntryInfo? = byName[name]

    private fun dataOffset(e: ZipEntryInfo): Long {
        val h = src.readFully(e.localHeaderOffset, 30)
        if (h.u32(0) != 0x04034b50L) throw IOException("ترويسة ملف تالفة: ${e.name}")
        return e.localHeaderOffset + 30 + h.u16(26) + h.u16(28)
    }

    /** للملفات غير المضغوطة فقط: مصدر بقراءة عشوائية بدون نسخ. */
    fun sourceOf(e: ZipEntryInfo): ByteSource? =
        if (e.isStored) src.slice(dataOffset(e), e.storedLength) else null

    fun open(e: ZipEntryInfo): InputStream {
        val off = dataOffset(e)
        return when (e.method) {
            8 -> {
                // نضيف بايت إضافياً لأن Inflater(nowrap=true) قد يحتاجه في النهاية
                val raw = src.openStream(off, minOf(e.compressedSize + 1, src.size - off))
                val inf = Inflater(true)
                object : FilterInputStream(InflaterInputStream(raw, inf, 64 * 1024)) {
                    override fun close() {
                        try { super.close() } finally { inf.end() }
                    }
                }
            }
            else -> src.openStream(off, minOf(e.storedLength, src.size - off))
        }
    }

    fun readBytes(e: ZipEntryInfo, limit: Long = 512L * 1024 * 1024): ByteArray {
        if ((if (e.isStored) e.storedLength else e.size) > limit) throw IOException("${e.name} كبير جداً للذاكرة")
        return open(e).use { it.readAllCompat(limit) }
    }

    /** يقرأ أول [n] بايت فقط. */
    fun readHead(e: ZipEntryInfo, n: Int): ByteArray {
        val want = minOf(n.toLong(), if (e.isStored) e.storedLength else e.size).toInt()
        val b = ByteArray(want)
        open(e).use { s ->
            var got = 0
            while (got < want) {
                val r = s.read(b, got, want - got)
                if (r < 0) break
                got += r
            }
            return if (got == want) b else b.copyOf(got)
        }
    }
}
