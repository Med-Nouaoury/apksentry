package io.github.mednouaoury.apksentry.core

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

class CertInfo(
    val subject: String,
    val sha256: String,
    val notBefore: Date,
    val notAfter: Date,
    val keyBits: Int?,
    val scheme: String,
) {
    fun dates(): Pair<String, String> {
        val f = SimpleDateFormat("yyyy-MM-dd", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
        return f.format(notBefore) to f.format(notAfter)
    }
}

/** يقرأ شهادات التوقيع: v1 (META-INF) و v2 و v3 (APK Signing Block). */
object Signing {
    private const val V2_ID = 0x7109871aL
    private const val V3_ID = 0xf05368c0L
    private const val V31_ID = 0x1b93ad61L
    private val V1_RE = Regex("META-INF/[^/]+\\.(RSA|DSA|EC)", RegexOption.IGNORE_CASE)

    fun read(zip: ZipArchive): List<CertInfo> {
        val out = ArrayList<CertInfo>()
        for (e in zip.entries) {
            if (!V1_RE.matches(e.name)) continue
            try {
                val certs = CertificateFactory.getInstance("X.509")
                    .generateCertificates(ByteArrayInputStream(zip.readBytes(e, 4L * 1024 * 1024)))
                for (c in certs) if (c is X509Certificate) out.add(info(c, "v1"))
            } catch (_: Exception) {
            }
        }
        try {
            out.addAll(signingBlock(zip))
        } catch (_: Exception) {
        }
        return out
    }

    private fun signingBlock(zip: ZipArchive): List<CertInfo> {
        val src = zip.src
        val cd = zip.centralDirOffset
        if (cd < 32) return emptyList()
        val footer = src.readFully(cd - 24, 24)
        if (String(footer, 8, 16, Charsets.ISO_8859_1) != "APK Sig Block 42") return emptyList()
        val blockSize = footer.u64(0)
        if (blockSize < 24 || blockSize > 32L * 1024 * 1024 || blockSize + 8 > cd) return emptyList()
        val start = cd - (blockSize + 8)
        val block = src.readFully(start, (blockSize + 8).toInt())
        if (block.u64(0) != blockSize) return emptyList()
        val out = ArrayList<CertInfo>()
        var p = 8
        val end = block.size - 24
        while (p + 12 <= end) {
            val len = block.u64(p)
            if (len < 4 || p + 8 + len > end) break
            val id = block.u32(p + 8)
            val scheme = when (id) {
                V2_ID -> "v2"
                V3_ID -> "v3"
                V31_ID -> "v3.1"
                else -> null
            }
            if (scheme != null) {
                val value = block.copyOfRange(p + 12, (p + 8 + len).toInt())
                out.addAll(parseSigners(value, scheme))
            }
            p += 8 + len.toInt()
        }
        return out
    }

    /** signers: [len][signer...] و signer: [len][signed data] حيث signed data = digests ثم certificates. */
    private fun parseSigners(v: ByteArray, scheme: String): List<CertInfo> {
        val out = ArrayList<CertInfo>()
        val cf = CertificateFactory.getInstance("X.509")
        var p = 4
        val signersEnd = minOf(v.size, 4 + v.i32(0))
        while (p + 4 <= signersEnd) {
            val signerLen = v.i32(p)
            val signer = p + 4
            if (signerLen <= 0 || signer + signerLen > v.size) break
            val sdLen = v.i32(signer)
            val sd = signer + 4
            val digestsLen = v.i32(sd)
            var c = sd + 4 + digestsLen
            val certsLen = v.i32(c)
            c += 4
            val certsEnd = minOf(c + certsLen, sd + sdLen)
            while (c + 4 <= certsEnd) {
                val cl = v.i32(c)
                if (cl <= 0 || c + 4 + cl > certsEnd) break
                try {
                    val cert = cf.generateCertificate(ByteArrayInputStream(v, c + 4, cl)) as X509Certificate
                    out.add(info(cert, scheme))
                } catch (_: Exception) {
                }
                c += 4 + cl
            }
            p = signer + signerLen
        }
        return out
    }

    private fun info(c: X509Certificate, scheme: String): CertInfo {
        val fp = MessageDigest.getInstance("SHA-256").digest(c.encoded).toHex()
        val bits = when (val k = c.publicKey) {
            is RSAPublicKey -> k.modulus.bitLength()
            is ECPublicKey -> k.params.order.bitLength()
            is DSAPublicKey -> k.params.p.bitLength()
            else -> null
        }
        return CertInfo(c.subjectX500Principal.name, fp, c.notBefore, c.notAfter, bits, scheme)
    }
}
