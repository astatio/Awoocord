package moe.lava.awoocord.voicee2ee.core

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.Random

/**
 * engine A -> relay A -> fake SFU -> relay B -> engine B over real localhost UDP. Each client has its own transport
 * key with the SFU (as with Discord); the DAVE frame layer must survive the SFU unchanged.
 */
class RelayTest {
    private val rnd = Random(3)
    private fun bytes(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }

    private val userA = 100L
    private val userB = 200L
    private val audioSsrcA = 1111L
    private val videoSsrcA = 2222L
    private val rtxSsrcA = 2223L
    private val vp8Pt = 103
    private val rtxPt = 104

    private lateinit var sfu: DatagramSocket
    private lateinit var relayA: MediaRelay
    private lateinit var relayB: MediaRelay
    private lateinit var engineA: DatagramSocket
    private lateinit var engineB: DatagramSocket
    private val keyA = bytes(32)
    private val keyB = bytes(32)
    @Volatile private var sfuRunning = true
    @Volatile private var relayBRemote: java.net.SocketAddress? = null
    /** RTP sequence numbers the SFU "loses" once. */
    private val dropOnce = java.util.Collections.synchronizedSet(HashSet<Int>())

    private val nopGateway = object : DaveGateway {
        override fun sendKeyPackage(keyPackage: ByteArray) {}
        override fun sendCommitWelcome(commitWelcome: ByteArray) {}
        override fun sendReadyForTransition(transitionId: Int) {}
        override fun sendInvalidCommitWelcome(transitionId: Int) {}
    }

    private fun ssrcs(ownAudio: Long) = SsrcMap().apply {
        ownAudioSsrc = ownAudio
        this.vp8Pt = this@RelayTest.vp8Pt
        vp8RtxPt = rtxPt
    }

    @Before
    fun setUp() {
        sfu = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        val sfuPort = sfu.localPort

        // shared DAVE sender key for A, installed as in an established group
        val base = bytes(16)
        val daveA = DaveProtocol(userA, 1, nopGateway, {}).apply { encryptor.setKeyRatchet(KeyRatchet(base)) }
        val daveB = DaveProtocol(userB, 1, nopGateway, {}).apply {
            decryptor(userA).transitionToKeyRatchet(KeyRatchet(base))
            decryptor(userA).transitionToPassthrough(false, 0)
        }
        relayA = MediaRelay("127.0.0.1", sfuPort, daveA, ssrcs(audioSsrcA).apply { ownVideo[videoSsrcA] = rtxSsrcA },
            TransportCipher.XSALSA20_LITE, { println("A: $it") })
        relayB = MediaRelay("127.0.0.1", sfuPort, daveB, ssrcs(9999).apply {
            users[audioSsrcA] = userA; users[videoSsrcA] = userA; users[rtxSsrcA] = userA; rtxToMedia[rtxSsrcA] = videoSsrcA
        }, TransportCipher.AES256_GCM, { println("B: $it") })
        relayA.setServerKey(TransportCipher.AES256_GCM, keyA)
        relayB.setServerKey(TransportCipher.XCHACHA20, keyB)

        engineA = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        engineB = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0)).apply { soTimeout = 3000 }

        // SFU: packets from relay A are re-keyed for relay B; relay B announces itself with a discovery-like packet
        Thread {
            val openA = TransportCipher.create(TransportCipher.AES256_GCM, keyA)!!
            val sealB = TransportCipher.create(TransportCipher.XCHACHA20, keyB)!!
            val buf = ByteArray(4096)
            while (sfuRunning) {
                val p = DatagramPacket(buf, buf.size)
                try { sfu.receive(p) } catch (e: Exception) { break }
                if (!Rtp.isRtpOrRtcp(buf, p.length)) {
                    relayBRemote = p.socketAddress
                    sfu.send(DatagramPacket(buf, 0, p.length, p.socketAddress)) // echo "discovery"
                    continue
                }
                val plain = openA.open(buf, p.length) ?: continue // e.g. relay B's own RTCP
                if (Rtp.payloadType(plain) == vp8Pt && dropOnce.remove(Rtp.seq(plain))) continue
                val target = relayBRemote ?: continue
                val wire = sealB.seal(plain)
                sfu.send(DatagramPacket(wire, wire.size, target))
            }
        }.apply { isDaemon = true }.start()

        // engine B "IP discovery" through relay B: teaches relay B the engine address and the SFU relay B's address
        val discovery = ByteArray(74).also { it[1] = 1 }
        engineB.send(DatagramPacket(discovery, discovery.size, InetSocketAddress("127.0.0.1", relayB.localPort)))
        val echo = DatagramPacket(ByteArray(100), 100)
        engineB.receive(echo)
        assertEquals("discovery is forwarded untouched both ways", 74, echo.length)
    }

    @After
    fun tearDown() {
        sfuRunning = false
        relayA.close(); relayB.close(); sfu.close(); engineA.close(); engineB.close()
    }

    private val engineSealA by lazy { TransportCipher.create(TransportCipher.XSALSA20_LITE, relayA.localKey)!! }
    private val engineOpenB by lazy { TransportCipher.create(TransportCipher.AES256_GCM, relayB.localKey)!! }

    private fun rtp(pt: Int, ssrc: Long, seq: Int, ts: Long, marker: Boolean, payload: ByteArray, ext: Boolean = false): ByteArray {
        val h = ByteArray(12)
        h[0] = (0x80 or if (ext) 0x10 else 0).toByte()
        h[1] = ((if (marker) 0x80 else 0) or pt).toByte()
        Bytes.putU16(h, 2, seq); Bytes.putU32(h, 4, ts); Bytes.putU32(h, 8, ssrc)
        val e = if (ext) byteArrayOf(0xBE.toByte(), 0xDE.toByte(), 0, 1, 0x10, 0x42, 0, 0) else ByteArray(0)
        return Bytes.concat(h, e, payload)
    }

    private fun engineASend(plain: ByteArray) {
        val wire = engineSealA.seal(plain)
        engineA.send(DatagramPacket(wire, wire.size, InetSocketAddress("127.0.0.1", relayA.localPort)))
    }

    private fun engineBReceive(): RtpParts {
        val p = DatagramPacket(ByteArray(4096), 4096)
        engineB.receive(p)
        val plain = engineOpenB.open(p.data, p.length) ?: error("engine B could not open")
        return RtpParts.parse(plain)!!
    }

    @Test
    fun opusFramesArriveDecrypted() {
        repeat(5) { i ->
            val opus = bytes(60 + i)
            engineASend(rtp(120, audioSsrcA, 10 + i, 960L * i, false, opus, ext = i % 2 == 0))
            val got = engineBReceive()
            assertArrayEquals(opus, got.payload)
            assertEquals(10 + i, got.seq)
            assertEquals(i % 2 == 0, got.extBody.isNotEmpty())
        }
        assertEquals(5L, relayA.sentFrames)
        assertEquals(5L, relayB.receivedFrames)
    }

    @Test
    fun vp8FramesSpanningPacketsAndRtx() {
        // key frame (P=0) split over 3 packets: descriptor (S=1 on the first), then VP8 data
        val frame = bytes(2500).also { it[0] = 0x10 }
        val chunks = listOf(frame.copyOfRange(0, 1000), frame.copyOfRange(1000, 2000), frame.copyOfRange(2000, 2500))
        val packets = chunks.mapIndexed { i, c ->
            val desc = byteArrayOf(if (i == 0) 0x10 else 0x00)
            rtp(vp8Pt, videoSsrcA, 500 + i, 90000, i == 2, desc + c)
        }
        // the SFU loses seq 501; engine B can only complete the frame through the engine A's RTX retransmission
        dropOnce.add(501)
        packets.forEach { engineASend(it) }
        Thread.sleep(200)
        val original = RtpParts.parse(packets[1])!!.payload // engines retransmit their own (plain) payload
        val osn = byteArrayOf(0x01, 0xF5.toByte()) // 501
        engineASend(rtp(rtxPt, rtxSsrcA, 42, 90000, false, osn + original))

        val got = (0 until 3).map { engineBReceive() }.sortedBy { it.seq }
        assertEquals(listOf(500, 501, 502), got.map { it.seq })
        val reassembled = got.map { it.payload.copyOfRange(Vp8.descriptorSize(it.payload), it.payload.size) }
            .reduce { a, b -> a + b }
        assertArrayEquals("the frame arrives decrypted, footer removed", frame, reassembled)
        assertTrue(got.last().marker)
    }

    private fun sendFromEngineA(cipher: TransportCipher, plain: ByteArray) {
        val wire = cipher.seal(plain)
        engineA.send(DatagramPacket(wire, wire.size, InetSocketAddress("127.0.0.1", relayA.localPort)))
    }

    @Test
    fun engineLayoutIsDetectedForOutgoingAudio() {
        // engine A encrypts its side with a layout other than the documented one
        val engine = XSalsaLiteRtpSize(relayA.localKey, rtpsizeHeader = false)
        repeat(3) { i ->
            val opus = bytes(70)
            sendFromEngineA(engine, rtp(120, audioSsrcA, 40 + i, 960L * i, false, opus, ext = true))
            assertArrayEquals(opus, engineBReceive().payload)
        }
        assertEquals("fixed header", relayA.localLayout)
        assertEquals(1L, relayA.engineUnreadable) // only the first packet needed probing
    }

    @Test
    fun detectedLayoutIsAlsoUsedTowardsTheEngine() {
        // engine B uses AES-GCM with the counter at the end of the nonce; its first RTCP packet reveals that
        val engineB2 = AesGcmRtpSize(relayB.localKey, noncePos = 8)
        val rr = ByteArray(8).also { it[0] = 0x80.toByte(); it[1] = 201.toByte(); Bytes.putU16(it, 2, 1) }
        val wire = engineB2.seal(rr)
        engineB.send(DatagramPacket(wire, wire.size, InetSocketAddress("127.0.0.1", relayB.localPort)))
        Thread.sleep(200)
        assertEquals("rtpsize, nonce last", relayB.localLayout)
        val opus = bytes(50)
        engineASend(rtp(120, audioSsrcA, 7, 960, false, opus))
        val p = DatagramPacket(ByteArray(4096), 4096)
        engineB.receive(p)
        val plain = engineB2.open(p.data, p.length) ?: error("engine B can't read the relay with its own layout")
        assertArrayEquals(opus, RtpParts.parse(plain)!!.payload)
    }

    @Test
    fun unencryptedEngineIsDetectedAfterEnoughEvidence() {
        val opus = bytes(40)
        repeat(30) { i -> engineA.send(rtp(120, audioSsrcA, 100 + i, 960L * i, false, opus).let {
            DatagramPacket(it, it.size, InetSocketAddress("127.0.0.1", relayA.localPort))
        }) }
        var got = 0
        try {
            while (true) { assertArrayEquals(opus, engineBReceive().payload); got++ }
        } catch (_: SocketTimeoutException) {
        }
        assertEquals("unencrypted", relayA.localLayout)
        assertTrue("frames flow once detected ($got)", got >= 5)
    }
}
