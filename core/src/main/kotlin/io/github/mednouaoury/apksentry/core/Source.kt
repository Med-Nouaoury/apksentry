package io.github.mednouaoury.apksentry.core

import java.io.Closeable
import java.io.EOFException
import java.io.File
import java.io.InputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/** مصدر بايتات بقراءة عشوائية (ملف، جزء من ملف، أو مصفوفة في الذاكرة). */
interface ByteSource : Closeable {
    val size: Long

    /** يقرأ حتى [len] بايت ابتداءً من [pos]. يرجع عدد البايتات المقروءة أو -1 في النهاية. */
    fun read(pos: Long, buf: ByteArray, off: Int, len: Int): Int

    override fun close() {}
}

fun ByteSource.readFully(pos: Long, len: Int): ByteArray {
    val b = ByteArray(len)
    var n = 0
    while (n < len) {
        val r = read(pos + n, b, n, len - n)
        if (r <= 0) throw EOFException("unexpected end of data at ${pos + n}")
        n += r
    }
    return b
}

fun ByteSource.slice(offset: Long, length: Long): ByteSource = SliceSource(this, offset, length)

fun ByteSource.openStream(start: Long = 0, length: Long = size - start): InputStream =
    SourceInputStream(this, start, length)

class FileChannelSource(private val channel: FileChannel, private val owner: Closeable? = null) : ByteSource {
    override val size: Long = channel.size()

    override fun read(pos: Long, buf: ByteArray, off: Int, len: Int): Int {
        if (pos >= size) return -1
        return channel.read(ByteBuffer.wrap(buf, off, len), pos)
    }

    override fun close() {
        try { channel.close() } finally { owner?.close() }
    }

    companion object {
        fun open(file: File): FileChannelSource {
            val raf = RandomAccessFile(file, "r")
            return FileChannelSource(raf.channel, raf)
        }
    }
}

class ByteArraySource(private val data: ByteArray) : ByteSource {
    override val size: Long = data.size.toLong()

    override fun read(pos: Long, buf: ByteArray, off: Int, len: Int): Int {
        if (pos >= size) return -1
        val n = minOf(len.toLong(), size - pos).toInt()
        System.arraycopy(data, pos.toInt(), buf, off, n)
        return n
    }
}

class SliceSource(private val parent: ByteSource, private val offset: Long, length: Long) : ByteSource {
    override val size: Long = maxOf(0L, minOf(length, parent.size - offset))

    override fun read(pos: Long, buf: ByteArray, off: Int, len: Int): Int {
        if (pos >= size) return -1
        val n = minOf(len.toLong(), size - pos).toInt()
        return parent.read(offset + pos, buf, off, n)
    }
}

/** InputStream فوق مصدر، يدعم skip سريع (قفز بدون قراءة). */
class SourceInputStream(private val src: ByteSource, start: Long, length: Long) : InputStream() {
    private var pos = start
    private val end = minOf(src.size, start + length)
    private val one = ByteArray(1)

    override fun read(): Int = if (read(one, 0, 1) <= 0) -1 else one[0].toInt() and 0xff

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        if (pos >= end) return -1
        val n = minOf(len.toLong(), end - pos).toInt()
        val r = src.read(pos, b, off, n)
        if (r > 0) pos += r
        return r
    }

    override fun skip(n: Long): Long {
        if (n <= 0) return 0
        val k = minOf(n, end - pos)
        pos += k
        return k
    }

    override fun available(): Int = minOf(Int.MAX_VALUE.toLong(), end - pos).toInt()
}

// ---------------- قراءة الأرقام (little-endian) ----------------
internal fun ByteArray.u8(o: Int): Int = this[o].toInt() and 0xff
internal fun ByteArray.u16(o: Int): Int = u8(o) or (u8(o + 1) shl 8)
internal fun ByteArray.u32(o: Int): Long = (u16(o).toLong()) or (u16(o + 2).toLong() shl 16)
internal fun ByteArray.i32(o: Int): Int = u32(o).toInt()
internal fun ByteArray.u64(o: Int): Long = u32(o) or (u32(o + 4) shl 32)

internal fun ByteArray.indexOf(pattern: ByteArray, from: Int = 0, until: Int = size): Int {
    if (pattern.isEmpty()) return from
    val first = pattern[0]
    val last = until - pattern.size
    var i = from
    outer@ while (i <= last) {
        if (this[i] != first) { i++; continue }
        for (j in 1 until pattern.size) if (this[i + j] != pattern[j]) { i++; continue@outer }
        return i
    }
    return -1
}

internal fun ByteArray.contains(pattern: ByteArray): Boolean = indexOf(pattern) >= 0

internal fun ByteArray.toHex(): String {
    val hex = "0123456789abcdef"
    val sb = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xff
        sb.append(hex[v ushr 4]).append(hex[v and 0xf])
    }
    return sb.toString()
}

/** يقرأ InputStream إلى نهايته (لا نستعمل readAllBytes لأنه غير موجود في أندرويد القديم). */
internal fun InputStream.readAllCompat(limit: Long = Int.MAX_VALUE.toLong() - 16): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(64 * 1024)
    var total = 0L
    while (true) {
        val r = read(buf)
        if (r < 0) break
        total += r
        if (total > limit) throw IllegalStateException("data too large")
        out.write(buf, 0, r)
    }
    return out.toByteArray()
}
