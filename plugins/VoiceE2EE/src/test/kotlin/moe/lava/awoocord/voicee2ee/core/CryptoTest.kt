package moe.lava.awoocord.voicee2ee.core

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.mls.crypto.MlsCipherSuite
import org.bouncycastle.mls.crypto.Secret
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Random

class CryptoTest {
    private val rnd = Random(1234)
    private fun bytes(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }

    @Test
    fun leb128RoundTrip() {
        val pos = IntArray(1)
        for (v in longArrayOf(0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0xFFFFFFFFL, 0x7FFFFFFFFFFFFFFFL, -1L)) {
            val buf = ByteArray(10)
            val n = Leb128.write(v, buf, 0)
            assertEquals(Leb128.size(v), n)
            assertEquals(v, Leb128.read(buf, 0, n, pos))
            assertEquals(n, pos[0])
        }
        // truncated input
        Leb128.read(byteArrayOf(0x80.toByte()), 0, 1, pos)
        assertEquals(-1, pos[0])
    }

    @Test
    fun treeSecretMatchesBcmls() {
        val suite = MlsCipherSuite.getSuite(MlsCipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
        val secret = bytes(16)
        for (gen in intArrayOf(0, 1, 7, 300)) {
            for ((label, len) in listOf("key" to 16, "secret" to 32)) {
                val expected = Secret(secret).deriveTreeSecret(suite, label, gen, len).value()
                assertArrayEquals(expected, MlsKdf.deriveTreeSecret(secret, label, gen.toLong(), len))
            }
        }
    }

    @Test
    fun ratchetGenerationsAreChained() {
        val base = bytes(16)
        val r = KeyRatchet(base)
        val k3 = r.get(3)!!
        // manual chain
        var s = base
        var k = ByteArray(0)
        for (g in 0..3) {
            k = MlsKdf.deriveTreeSecret(s, "key", g.toLong(), 16)
            s = MlsKdf.deriveTreeSecret(s, "secret", g.toLong(), 32)
        }
        assertArrayEquals(k, k3)
        r.erase(1)
        assertNull(r.get(1)) // erased generations are gone
        assertArrayEquals(k3, KeyRatchet(base).get(3))
    }

    @Test
    fun aesGcm64MatchesBouncyCastleTruncatedTag() {
        repeat(50) { i ->
            val key = bytes(16)
            val nonce = bytes(12)
            val aad = bytes(i % 11)
            val pt = bytes(i * 37 % 1500)

            val bc = GCMBlockCipher.newInstance(AESEngine.newInstance())
            bc.init(true, AEADParameters(KeyParameter(key), 64, nonce, aad))
            val bcOut = ByteArray(bc.getOutputSize(pt.size))
            bc.doFinal(bcOut, bc.processBytes(pt, 0, pt.size, bcOut, 0))

            val tag = ByteArray(8)
            val ct = AesGcm64(key).encrypt(nonce, pt, aad, tag, 0)
            assertArrayEquals(bcOut, ct + tag)

            assertArrayEquals(pt, AesGcm64(key).decrypt(nonce, ct, aad, tag, 0))
            if (ct.isNotEmpty()) {
                val bad = ct.clone().also { it[0] = (it[0] + 1).toByte() }
                assertNull(AesGcm64(key).decrypt(nonce, bad, aad, tag, 0))
            }
            val badTag = tag.clone().also { it[7] = (it[7] + 1).toByte() }
            assertNull(AesGcm64(key).decrypt(nonce, ct, aad, badTag, 0))
        }
    }
}
