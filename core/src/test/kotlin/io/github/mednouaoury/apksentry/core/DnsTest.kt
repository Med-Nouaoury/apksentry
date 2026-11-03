package io.github.mednouaoury.apksentry.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsTest {
    /** حزمة IPv4/UDP فيها طلب DNS لـ [domain] من 10.0.0.2:40000 إلى 10.111.222.2:53. */
    private fun queryPacket(domain: String, id: Int = 0x1234): ByteArray {
        val q = java.io.ByteArrayOutputStream()
        q.write(byteArrayOf((id ushr 8).toByte(), id.toByte(), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0))
        for (label in domain.split('.')) { q.write(label.length); q.write(label.toByteArray()) }
        q.write(byteArrayOf(0, 0, 1, 0, 1))
        val dns = q.toByteArray()
        val p = ByteArray(28 + dns.size)
        p[0] = 0x45; p[2] = (p.size ushr 8).toByte(); p[3] = p.size.toByte(); p[8] = 64; p[9] = 17
        byteArrayOf(10, 0, 0, 2).copyInto(p, 12); byteArrayOf(10, 111, 222.toByte(), 2).copyInto(p, 16)
        p[20] = (40000 ushr 8).toByte(); p[21] = 40000.toByte(); p[23] = 53
        p[24] = ((8 + dns.size) ushr 8).toByte(); p[25] = (8 + dns.size).toByte()
        dns.copyInto(p, 28)
        return p
    }

    @Test
    fun parsesQueryAndBuildsBlockingAnswer() {
        val q = assertNotNull(DnsPackets.parseQuery(queryPacket("ApkVision.org")))
        assertEquals("apkvision.org", q.domain)
        assertEquals("A", q.typeName)
        val nx = DnsPackets.nxdomain(q)
        assertEquals(3, DnsPackets.rcode(nx))
        assertEquals(0x12, nx[0].toInt()); assertEquals(0x34, nx[1].toInt())
        assertEquals("apkvision.org" to 1, DnsPackets.question(nx))
        val pkt = DnsPackets.wrapResponse(q, nx)
        // الرد يرجع من الخادم الوهمي إلى التطبيق، والـ checksum صحيح
        assertEquals(10, pkt[12].toInt()); assertEquals(2, pkt[19].toInt())
        assertEquals(0, DnsPackets.checksum(pkt, 0, 20))
        assertEquals(53, ((pkt[20].toInt() and 0xff) shl 8) or (pkt[21].toInt() and 0xff))
        assertEquals(40000, ((pkt[22].toInt() and 0xff) shl 8) or (pkt[23].toInt() and 0xff))
    }

    @Test
    fun readsAnswerIps() {
        val q = DnsPackets.parseQuery(queryPacket("example.com"))!!
        val base = q.payload.copyOf()
        base[2] = 0x81.toByte(); base[3] = 0x80.toByte(); base[7] = 1
        val ans = byteArrayOf(0xc0.toByte(), 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184.toByte(), 216.toByte(), 34)
        assertEquals(listOf("93.184.216.34"), DnsPackets.answerIps(base + ans))
    }

    @Test
    fun ignoresNonDnsAndGarbage() {
        val p = queryPacket("a.b")
        p[23] = 80
        assertNull(DnsPackets.parseQuery(p))
        val rnd = java.util.Random(1)
        repeat(2000) { DnsPackets.parseQuery(ByteArray(rnd.nextInt(80)) { rnd.nextInt(256).toByte() }) }
    }

    @Test
    fun classifiesDomains() {
        val site = DomainIntel.repackTokens("CN=APKVISION.ORG,OU=APKVISION.ORG,O=APKVISION.ORG")
        assertTrue("apkvision" in site)
        assertEquals(DomainKind.SUSPICIOUS, DomainIntel.classify("apkvision.org", site))
        assertEquals(DomainKind.KNOWN, DomainIntel.classify("mtalk.google.com", site))
        assertEquals(DomainKind.TRACKING, DomainIntel.classify("app-measurement.com", emptySet()))
        assertEquals(DomainKind.UNUSUAL, DomainIntel.classify("weird-c2.xyz", emptySet()))
        // المطور الحقيقي يتصل بموقعه: ليس مشبوهاً
        val official = DomainIntel.repackTokens("CN=Rockstar Games,O=Rockstar Games,L=New York")
        assertTrue(official.isEmpty())
        assertEquals(DomainKind.KNOWN, DomainIntel.classify("prod.rockstargames.com", official))
    }
}
