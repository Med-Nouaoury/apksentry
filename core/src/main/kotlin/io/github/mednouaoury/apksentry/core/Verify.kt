package io.github.mednouaoury.apksentry.core

import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec

enum class IntegrityStatus { VERIFIED, FAILED, UNSUPPORTED, NO_V2 }

class Integrity(val status: IntegrityStatus, val scheme: String = "", val detail: String = "")

/**
 * التحقق الحقيقي من التوقيع (APK Signature Scheme v2 و v3):
 * 1) نتحقق أن التوقيع على البيانات الموقّعة صحيح بالمفتاح العام.
 * 2) نتحقق أن المفتاح العام هو نفسه مفتاح الشهادة.
 * 3) نحسب بصمة محتوى الملف كله (قطعاً من 1 ميجا) ونقارنها بالبصمة الموقّعة.
 * إذا تغيّر بايت واحد بعد التوقيع، يفشل التحقق.
 */
object ApkVerifier {
    private const val V2_ID = 0x7109871aL
    private const val V3_ID = 0xf05368c0L
    private const val CHUNK = 1 shl 20

    private class Algo(val id: Int, val jca: String, val digest: String, val pss: Boolean, val strength: Int)

    private val ALGOS = listOf(
        Algo(0x0101, "SHA256withRSA/PSS", "SHA-256", true, 2),
        Algo(0x0102, "SHA512withRSA/PSS", "SHA-512", true, 4),
        Algo(0x0103, "SHA256withRSA", "SHA-256", false, 1),
        Algo(0x0104, "SHA512withRSA", "SHA-512", false, 3),
        Algo(0x0201, "SHA256withECDSA", "SHA-256", false, 1),
        Algo(0x0202, "SHA512withECDSA", "SHA-512", false, 3),
        Algo(0x0301, "SHA256withDSA", "SHA-256", false, 0),
    ).associateBy { it.id }

    fun verify(zip: ZipArchive, checkCancel: () -> Unit, onProgress: (Float) -> Unit = {}): Integrity {
        val src = zip.src
        val cd = zip.centralDirOffset
        val eocd = zip.eocdOffset
        if (cd < 32 || eocd < cd) return Integrity(IntegrityStatus.NO_V2)
        val footer = src.readFully(cd - 24, 24)
        if (String(footer, 8, 16, Charsets.ISO_8859_1) != "APK Sig Block 42") return Integrity(IntegrityStatus.NO_V2)
        val blockSize = footer.u64(0)
        if (blockSize < 24 || blockSize > 32L * 1024 * 1024 || blockSize + 8 > cd) return Integrity(IntegrityStatus.FAILED, detail = "حجم كتلة التوقيع غير صالح")
        val blockStart = cd - (blockSize + 8)
        val block = src.readFully(blockStart, (blockSize + 8).toInt())
        if (block.u64(0) != blockSize) return Integrity(IntegrityStatus.FAILED, detail = "كتلة التوقيع تالفة")

        var v2: ByteArray? = null
        var v3: ByteArray? = null
        var p = 8
        val end = block.size - 24
        while (p + 12 <= end) {
            val len = block.u64(p)
            if (len < 4 || p + 8 + len > end) return Integrity(IntegrityStatus.FAILED, detail = "كتلة التوقيع تالفة")
            when (block.u32(p + 8)) {
                V2_ID -> v2 = block.copyOfRange(p + 12, (p + 8 + len).toInt())
                V3_ID -> v3 = block.copyOfRange(p + 12, (p + 8 + len).toInt())
            }
            p += 8 + len.toInt()
        }
        val (scheme, value) = when {
            v3 != null -> "v3" to v3
            v2 != null -> "v2" to v2
            else -> return Integrity(IntegrityStatus.NO_V2)
        }
        return try {
            verifySigners(value, scheme == "v3", src, blockStart, cd, eocd, checkCancel, onProgress, scheme)
        } catch (e: ScanCancelledException) {
            throw e
        } catch (e: Exception) {
            Integrity(IntegrityStatus.FAILED, scheme, "بنية التوقيع تالفة (${e.javaClass.simpleName})")
        }
    }

    private class Reader(val b: ByteArray, var p: Int = 0, val end: Int = b.size) {
        fun u32(): Int { require(p + 4 <= end); val v = b.i32(p); p += 4; return v }
        fun lp(): Reader {
            val n = u32()
            require(n >= 0 && p + n <= end)
            val r = Reader(b, p, p + n)
            p += n
            return r
        }
        fun bytes(): ByteArray = b.copyOfRange(p, end)
        val left get() = end - p
    }

    private fun verifySigners(
        value: ByteArray, isV3: Boolean, src: ByteSource, blockStart: Long, cd: Long, eocd: Long,
        checkCancel: () -> Unit, onProgress: (Float) -> Unit, scheme: String,
    ): Integrity {
        val signers = Reader(value).lp()
        var computed: Map<String, ByteArray>? = null
        var count = 0
        while (signers.left > 0) {
            val signer = signers.lp()
            val signedDataReader = signer.lp()
            val signedData = signedDataReader.bytes()
            if (isV3) { signer.u32(); signer.u32() } // minSdk, maxSdk
            val sigs = signer.lp()
            val pubKey = signer.lp().bytes()

            // أقوى خوارزمية مدعومة
            var best: Pair<Algo, ByteArray>? = null
            while (sigs.left > 0) {
                val s = sigs.lp()
                val algo = ALGOS[s.u32()] ?: continue
                val sig = s.lp().bytes()
                if (best == null || algo.strength > best.first.strength) best = algo to sig
            }
            val (algo, sigBytes) = best ?: return Integrity(IntegrityStatus.UNSUPPORTED, scheme, "خوارزمية توقيع غير مدعومة")
            val keyAlg = when {
                algo.jca.endsWith("RSA") || algo.pss -> "RSA"
                algo.jca.endsWith("ECDSA") -> "EC"
                else -> "DSA"
            }
            val key = KeyFactory.getInstance(keyAlg).generatePublic(X509EncodedKeySpec(pubKey))
            if (!checkSignature(algo, key, signedData, sigBytes)) return Integrity(IntegrityStatus.FAILED, scheme, "التوقيع لا يطابق البيانات الموقّعة")

            // الشهادة يجب أن تحمل نفس المفتاح
            val sd = Reader(signedData)
            val digests = sd.lp()
            val certs = sd.lp()
            val firstCert = certs.lp().bytes()
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(firstCert))
            if (!cert.publicKey.encoded.contentEquals(pubKey)) return Integrity(IntegrityStatus.FAILED, scheme, "مفتاح الشهادة لا يطابق مفتاح التوقيع")

            // بصمة المحتوى
            var expected: ByteArray? = null
            while (digests.left > 0) {
                val d = digests.lp()
                val id = d.u32()
                val dig = d.lp().bytes()
                if (id == algo.id) expected = dig
            }
            if (expected == null) return Integrity(IntegrityStatus.FAILED, scheme, "لا توجد بصمة للمحتوى")
            val have = computed ?: emptyMap()
            if (algo.digest !in have) computed = have + contentDigests(src, blockStart, cd, eocd, listOf(algo.digest), checkCancel, onProgress)
            val actual = computed!![algo.digest] ?: return Integrity(IntegrityStatus.UNSUPPORTED, scheme)
            if (!actual.contentEquals(expected)) return Integrity(IntegrityStatus.FAILED, scheme, "محتوى الملف تغيّر بعد التوقيع")
            count++
        }
        return if (count > 0) Integrity(IntegrityStatus.VERIFIED, scheme) else Integrity(IntegrityStatus.FAILED, scheme, "لا يوجد موقِّع")
    }

    private fun checkSignature(algo: Algo, key: java.security.PublicKey, data: ByteArray, sig: ByteArray): Boolean {
        val s: Signature = if (algo.pss) {
            val md = algo.digest
            try {
                Signature.getInstance(algo.jca) // أندرويد
            } catch (e: Exception) {
                Signature.getInstance("RSASSA-PSS").apply { // جافا على الحاسوب
                    setParameter(PSSParameterSpec(md, "MGF1", if (md == "SHA-256") MGF1ParameterSpec.SHA256 else MGF1ParameterSpec.SHA512, if (md == "SHA-256") 32 else 64, 1))
                }
            }
        } else Signature.getInstance(algo.jca)
        s.initVerify(key)
        s.update(data)
        return s.verify(sig)
    }

    /** بصمة المحتوى حسب المواصفة: كل قطعة H(0xa5|طول|بيانات)، ثم H(0x5a|عدد|البصمات). */
    private fun contentDigests(
        src: ByteSource, blockStart: Long, cd: Long, eocd: Long, algs: List<String>,
        checkCancel: () -> Unit, onProgress: (Float) -> Unit,
    ): Map<String, ByteArray> {
        val eocdBytes = src.readFully(eocd, (src.size - eocd).toInt().coerceAtMost(65_557))
        // في EOCD نضع بداية كتلة التوقيع مكان موقع الفهرس
        eocdBytes[16] = blockStart.toByte(); eocdBytes[17] = (blockStart ushr 8).toByte()
        eocdBytes[18] = (blockStart ushr 16).toByte(); eocdBytes[19] = (blockStart ushr 24).toByte()
        val sections = listOf(src.slice(0, blockStart), src.slice(cd, eocd - cd), ByteArraySource(eocdBytes))
        val total = sections.sumOf { it.size }
        val chunkDigests = algs.associateWith { java.io.ByteArrayOutputStream() }
        var chunks = 0
        var done = 0L
        val buf = ByteArray(CHUNK)
        val mds = algs.associateWith { MessageDigest.getInstance(it) }
        for (s in sections) {
            var off = 0L
            while (off < s.size) {
                checkCancel()
                val n = minOf(CHUNK.toLong(), s.size - off).toInt()
                var got = 0
                while (got < n) {
                    val r = s.read(off + got, buf, got, n - got)
                    if (r <= 0) throw java.io.EOFException()
                    got += r
                }
                val prefix = byteArrayOf(0xa5.toByte(), n.toByte(), (n ushr 8).toByte(), (n ushr 16).toByte(), (n ushr 24).toByte())
                for (a in algs) {
                    val md = mds.getValue(a)
                    md.reset(); md.update(prefix); md.update(buf, 0, n)
                    chunkDigests.getValue(a).write(md.digest())
                }
                chunks++
                off += n
                done += n
                if (chunks % 16 == 0) onProgress(done.toFloat() / total)
            }
        }
        return algs.associateWith { a ->
            val md = MessageDigest.getInstance(a)
            md.update(byteArrayOf(0x5a, chunks.toByte(), (chunks ushr 8).toByte(), (chunks ushr 16).toByte(), (chunks ushr 24).toByte()))
            md.update(chunkDigests.getValue(a).toByteArray())
            md.digest()
        }
    }
}
