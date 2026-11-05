package moe.lava.awoocord.voicee2ee.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Random

class TransportTest {
    private val rnd = Random(5)
    private fun bytes(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }
    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    @Test
    fun hChaCha20Vector() {
        // draft-irtf-cfrg-xchacha-03, section 2.2.1
        val key = ByteArray(32) { it.toByte() }
        val nonce = hex("000000090000004a0000000031415927")
        val expected = hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
        assertArrayEquals(expected, XChaChaRtpSize.hChaCha20(key, nonce))
    }

    private fun rtp(ext: Boolean, payload: ByteArray, pt: Int = 120): ByteArray {
        val h = ByteArray(12)
        h[0] = (0x80 or if (ext) 0x10 else 0).toByte()
        h[1] = pt.toByte()
        Bytes.putU16(h, 2, 777)
        Bytes.putU32(h, 4, 123456)
        Bytes.putU32(h, 8, 0xCAFEBABEL)
        val e = if (ext) byteArrayOf(0xBE.toByte(), 0xDE.toByte(), 0, 1, 0x10, 0x55, 0, 0) else ByteArray(0)
        return Bytes.concat(h, e, payload)
    }

    @Test
    fun allModesRoundTripAndAuthenticateHeader() {
        for (mode in listOf(TransportCipher.AES256_GCM, TransportCipher.XCHACHA20, TransportCipher.XSALSA20_LITE)) {
            val key = bytes(32)
            val a = TransportCipher.create(mode, key)!!
            val b = TransportCipher.create(mode, key)!!
            for (ext in listOf(false, true)) {
                val plain = rtp(ext, bytes(90))
                val wire = a.seal(plain)
                assertEquals(mode, plain.size + 16 + 4, wire.size)
                // rtpsize: fixed header and extension header stay clear, the extension body does not
                val clear = if (ext) 16 else 12
                assertArrayEquals(plain.copyOf(clear), wire.copyOf(clear))
                assertArrayEquals(mode, plain, b.open(wire, wire.size))
                val bad = wire.clone().also { it[wire.size - 6] = (it[wire.size - 6].toInt() xor 1).toByte() }
                assertNull(b.open(bad, bad.size))
                if (mode != TransportCipher.XSALSA20_LITE) { // the AEAD modes also authenticate the header
                    val badHdr = wire.clone().also { it[3] = (it[3].toInt() xor 1).toByte() }
                    assertNull(b.open(badHdr, badHdr.size))
                }
            }
        }
    }

    @Test
    fun aesNonceLayoutMatchesDiscord() {
        // aead_aes256_gcm_rtpsize: 12 byte nonce = 4 byte big-endian counter + 8 zero bytes; counter appended to the packet
        val key = bytes(32)
        val c = TransportCipher.create(TransportCipher.AES256_GCM, key)!!
        val plain = rtp(false, bytes(20))
        val wire1 = c.seal(plain)
        val wire2 = c.seal(plain)
        assertArrayEquals(byteArrayOf(0, 0, 0, 1), wire1.copyOfRange(wire1.size - 4, wire1.size))
        assertArrayEquals(byteArrayOf(0, 0, 0, 2), wire2.copyOfRange(wire2.size - 4, wire2.size))
        val jce = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val nonce = ByteArray(12).also { it[3] = 1 }
        jce.init(javax.crypto.Cipher.ENCRYPT_MODE, javax.crypto.spec.SecretKeySpec(key, "AES"), javax.crypto.spec.GCMParameterSpec(128, nonce))
        jce.updateAAD(plain, 0, 12)
        assertArrayEquals(jce.doFinal(plain, 12, plain.size - 12), wire1.copyOfRange(12, wire1.size - 4))
    }

    @Test
    fun vp8DescriptorSizes() {
        assertEquals(1, Vp8.descriptorSize(byteArrayOf(0x10, 1)))
        assertEquals(3, Vp8.descriptorSize(byteArrayOf(0x90.toByte(), 0x80.toByte(), 0x05, 1)))
        assertEquals(4, Vp8.descriptorSize(byteArrayOf(0x90.toByte(), 0x80.toByte(), 0x85.toByte(), 0x01, 1)))
        assertEquals(6, Vp8.descriptorSize(byteArrayOf(0x90.toByte(), 0xF0.toByte(), 0x85.toByte(), 0x01, 7, 0x20, 1)))
        assertEquals(-1, Vp8.descriptorSize(byteArrayOf(0x90.toByte())))
    }
}
