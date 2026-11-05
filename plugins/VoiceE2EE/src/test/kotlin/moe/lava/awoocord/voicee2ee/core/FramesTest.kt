package moe.lava.awoocord.voicee2ee.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

class FramesTest {
    private val rnd = Random(99)
    private fun bytes(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }

    private class FakeClock(var now: Long = 1_000_000) : Clock {
        override fun nowMs() = now
    }

    private fun pair(base: ByteArray = bytes(16), clock: Clock = FakeClock()): Pair<FrameEncryptor, FrameDecryptor> {
        val enc = FrameEncryptor().apply { setKeyRatchet(KeyRatchet(base)) }
        val dec = FrameDecryptor(clock).apply {
            transitionToKeyRatchet(KeyRatchet(base))
            transitionToPassthrough(false, 0)
        }
        return enc to dec
    }

    @Test
    fun opusRoundTripAndLayout() {
        val (enc, dec) = pair()
        val frame = bytes(120)
        val out = enc.encrypt(Codec.OPUS, frame)!!
        // marker, supplemental size: tag(8) + nonce(1, nonce=1) + no ranges + size + marker
        assertEquals(0xFA.toByte(), out[out.size - 1])
        assertEquals(0xFA.toByte(), out[out.size - 2])
        assertEquals(8 + 1 + 1 + 2, out[out.size - 3].toInt())
        assertEquals(frame.size + 12, out.size)
        assertTrue("payload must be encrypted", !frame.contentEquals(out.copyOf(frame.size)))

        assertEquals(FrameDecryptor.Result.OK, dec.decrypt(true, out))
        assertArrayEquals(frame, dec.output)
        // replay of the same nonce is refused
        assertEquals(FrameDecryptor.Result.INVALID_NONCE, dec.decrypt(true, out))
    }

    @Test
    fun vp8KeyAndDeltaFramesKeepTheirHeaders() {
        val (enc, dec) = pair()
        val key = bytes(500).also { it[0] = (it[0].toInt() and 0xFE).toByte() } // P = 0: key frame
        val delta = bytes(300).also { it[0] = (it[0].toInt() or 1).toByte() } // P = 1: delta frame
        for ((frame, clear) in listOf(key to 10, delta to 1)) {
            val out = enc.encrypt(Codec.VP8, frame)!!
            assertArrayEquals(frame.copyOf(clear), out.copyOf(clear))
            val p = ProtocolFrame.parse(out)!!
            assertArrayEquals(longArrayOf(0, clear.toLong()), p.ranges)
            assertEquals(FrameDecryptor.Result.OK, dec.decrypt(false, out))
            assertArrayEquals(frame, dec.output)
        }
    }

    @Test
    fun tamperedAadOrCiphertextIsRejected() {
        val (enc, dec) = pair()
        val frame = bytes(200).also { it[0] = 0 }
        val out = enc.encrypt(Codec.VP8, frame)!!
        for (i in intArrayOf(0, 5, 50)) {
            val bad = out.clone().also { it[i] = (it[i].toInt() xor 1).toByte() }
            assertEquals(FrameDecryptor.Result.FAILED, dec.decrypt(false, bad))
        }
        assertEquals(FrameDecryptor.Result.OK, dec.decrypt(false, out))
    }

    @Test
    fun outOfOrderFramesWithinWindowDecrypt() {
        val (enc, dec) = pair()
        val frames = List(20) { bytes(60) }
        val sealed = frames.map { enc.encrypt(Codec.OPUS, it)!! }
        val order = (0 until 20).toMutableList().also { java.util.Collections.shuffle(it, rnd) }
        for (i in order) {
            assertEquals(FrameDecryptor.Result.OK, dec.decrypt(true, sealed[i]))
            assertArrayEquals(frames[i], dec.output)
        }
    }

    @Test
    fun silenceAndPassthrough() {
        val clock = FakeClock()
        val dec = FrameDecryptor(clock)
        val plain = bytes(40).also { it[it.size - 1] = 1 }
        // fresh decryptors pass unencrypted frames through (passthrough until a ratchet arrives)
        assertEquals(FrameDecryptor.Result.PASSTHROUGH, dec.decrypt(true, plain))
        dec.transitionToKeyRatchet(KeyRatchet(bytes(16)))
        dec.transitionToPassthrough(false, 10_000)
        assertEquals(FrameDecryptor.Result.PASSTHROUGH, dec.decrypt(true, plain)) // still within the transition window
        clock.now += 10_001
        assertEquals(FrameDecryptor.Result.NOT_ENCRYPTED, dec.decrypt(true, plain))
        // the SFU's synthetic Opus silence is always allowed
        assertEquals(FrameDecryptor.Result.PASSTHROUGH, dec.decrypt(true, ProtocolFrame.OPUS_SILENCE.clone()))

        val enc = FrameEncryptor()
        assertNull("no key yet: drop", enc.encrypt(Codec.OPUS, plain))
        enc.passthrough = true
        assertArrayEquals(plain, enc.encrypt(Codec.OPUS, plain))
    }

    @Test
    fun previousEpochKeysStayValidDuringTransition() {
        val clock = FakeClock()
        val oldBase = bytes(16)
        val newBase = bytes(16)
        val oldEnc = FrameEncryptor().apply { setKeyRatchet(KeyRatchet(oldBase)) }
        val newEnc = FrameEncryptor().apply { setKeyRatchet(KeyRatchet(newBase)) }
        val dec = FrameDecryptor(clock).apply {
            transitionToKeyRatchet(KeyRatchet(oldBase))
            transitionToKeyRatchet(KeyRatchet(newBase))
            transitionToPassthrough(false, 0)
        }
        val f = bytes(80)
        assertEquals(FrameDecryptor.Result.OK, dec.decrypt(true, newEnc.encrypt(Codec.OPUS, f)!!))
        assertEquals(FrameDecryptor.Result.OK, dec.decrypt(true, oldEnc.encrypt(Codec.OPUS, f)!!))
        clock.now += 10_001
        assertTrue(dec.decrypt(true, oldEnc.encrypt(Codec.OPUS, f)!!) != FrameDecryptor.Result.OK)
        assertEquals(FrameDecryptor.Result.OK, dec.decrypt(true, newEnc.encrypt(Codec.OPUS, f)!!))
    }

    @Test
    fun reinstallingTheSameRatchetKeepsTheNonceSequence() {
        val base = bytes(16)
        val enc = FrameEncryptor().apply { setKeyRatchet(KeyRatchet(base)) }
        val a = enc.encrypt(Codec.OPUS, bytes(10))!!
        enc.setKeyRatchet(KeyRatchet(base))
        val b = enc.encrypt(Codec.OPUS, bytes(10))!!
        assertEquals(1L, ProtocolFrame.parse(a)!!.truncatedNonce)
        assertEquals(2L, ProtocolFrame.parse(b)!!.truncatedNonce)
    }

    @Test
    fun nonProtocolFramesAreDetected() {
        assertNull(ProtocolFrame.parse(bytes(5)))
        val fake = bytes(30).also { it[29] = 0xFA.toByte(); it[28] = 0xFA.toByte(); it[27] = 200.toByte() }
        assertNull(ProtocolFrame.parse(fake))
        assertNotNull(ProtocolFrame.parse(FrameEncryptor().apply { setKeyRatchet(KeyRatchet(bytes(16))) }.encrypt(Codec.OPUS, bytes(3))!!))
    }
}
